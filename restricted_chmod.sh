#!/bin/bash
# /usr/local/bin/chmod 

set -euo pipefail

# -------------------------
# Block 디렉터리 정책 설정
# -------------------------

BLOCKED_PATHS=(
  "/"
  "/usr"
  "/bin"
  "/sbin"
  "/dev"
  "/lib"
  "/lib64"
  "/etc"
  "/opt"
  "/root"
  "/proc"
  "/sys"
  "/var"
  "/srv"
  "/boot"
  "/tmp"
  "/run"
  "/media"
  "/mnt"
  "/lost+found"
  "/home"
  "/data"
)

# -------------------------
# 반복 함수 설정
# -------------------------

die() { printf '\033[31;1m%b\033[m\n' "$*" >&2; exit 1; }

answer_check() {  
  local ans
  while :;do
    read -r -p "그래도 진행하시겠습니까?[y/n] " ans
    case "$ans" in
      y|Y) echo ""; return 0 ;;
      n|N) die "$1" ;;
      *) echo "다시 선택해주세요." ;;
    esac
  done
}

# -------------------------
# "/" 또는 "/등등" (루트 바로 하위)인지 검사
# -------------------------

is_root_or_immediate_child() {
  local p="$1" canon
  canon=$(readlink -f -- "$p") || return 1
  [[ "$canon" == "/" || "$canon" =~ ^/[^/]+/?$ ]] && return 0
}

# -------------------------
# BLOCKED_PATHS 배열에 포함되는지 검사
# -------------------------

is_in_blocklist() {
  local p="$1" canon b
  canon=$(readlink -f -- "$p") || return 1
  for b in "${BLOCKED_PATHS[@]}";do
    [[ "$canon" == "$b" || "$canon" == "$b"/ ]] && return 0
  done
  return 1
}

# -------------------------
# -R / --recursive 포함 여부
# -------------------------

contains_recursive() {
  local a
  for a in "$@";do
    [[ "$a" == "--" ]] && break
    case "$a" in
      --recursive|-*[R]* ) 
        return 0 
        ;;
    esac
  done
  return 1
}

# -------------------------
# reference 확인
# -------------------------

MODE=""; REF_MODE=0; FILES=(); REF_FILE=""
extract_mode_and_files() {
  local parsing_opts=1 a
  while (( $# ));do
    case "$1" in
      --) shift; break ;;
      --reference=*) REF_MODE=1; REF_FILE=${1#*=}; shift; break ;;
      --reference) REF_MODE=1; shift; 
                     (($#)) || break
                   REF_FILE="$1"
                   shift; break ;;
      -*) shift; continue ;;
      *) MODE="$1"; shift; break ;;
    esac
  done
  FILES=( "$@" )
}


# -------------------------
# 777 확인
# -------------------------

is_dangerous_777() {
  local m="$1"
  [[ "$m" =~ ^0*777 ]] && return 0
  if [[ $m =~ ^(a|ugo)?[+=][rwxstX]+$ ]]; then
    [[ $m == *r* && $m == *w* && $m == *x* && $m != *X* ]] && return 0
  fi
  return 1
}

# -------------------------
# 도움말
# -------------------------

is_help() {
  local a
  for a in "$@";do
    case "$a" in
      --) break ;;
      --help) exec /usr/bin/chmod --help; exit 0 ;;
    esac  
  done
}

# -------------------------
# Main 함수
# -------------------------

main() {
  local ORIG=( "$@" )

  is_help "${ORIG[@]}"

  extract_mode_and_files "${ORIG[@]}"

  (( ${#FILES[@]} > 0 )) || die "chmod: missing operand\nTry 'chmod --help' for more information."

  local f
  for f in "${FILES[@]}";do
    [[ "$f" == -* ]] && continue
    
    if is_in_blocklist "$f";then
      die "$f 경로는 변경이 불가능합니다."
    fi

    if is_root_or_immediate_child "$f";then
      echo -e "지금 적용하려고 하시는 \033[31;1m"$f"\033[m 경로는 / 경로 바로 하위 경로입니다."
      echo "원하시는 경로가 맞는지 확인 부탁드립니다."
      answer_check "해당 경로의 권한 변경을 취소합니다."
    fi
  done

  if contains_recursive "${ORIG[@]}";then
    echo "-R/--recursive 를 재귀 옵션을 사용했습니다."
    echo "해당 옵션은 사용 시, 하위 경로 모두 권한이 변경됩니다."
    answer_check "-R/--recursive 옵션으로 명령 실행이 취소됩니다."
  fi


  if (( REF_MODE == 0 )) && [[ -n "${MODE:-}" ]] && is_dangerous_777 "$MODE";then
    echo "777, rwx 권한은 보안적인 위험이 있으며,"
    echo "특정 파일의 권한이 777, rwx 로 권한이 변경될 경우, 시스템 운영에 악영향을 끼칩니다."
    answer_check "777, rwx 권한으로 명령 실행이 취소됩니다."
  fi

  if (( REF_MODE == 1 )) && [[ -n ${REF_FILE:-} ]]; then
    local ref_mode
    ref_mode=$(stat -c %a -- "$REF_FILE" 2>/dev/null || printf '')
    if [[ $ref_mode =~ ^[0-7]{3,4}$ ]] && is_dangerous_777 "$ref_mode"; then
      echo -e "--reference 대상(\e[31;1m${REF_FILE}\e[m)의 권한(\e[31;1m${ref_mode}\e[m)이 위험합니다."
      echo "777, rwx 권한은 보안적인 위험이 있으며,"
      echo "특정 파일의 권한이 777, rwx 로 권한이 변경될 경우, 시스템 운영에 악영향을 끼칩니다."
      answer_check "777, rwx 권한으로 명령 실행이 취소됩니다."
    fi
  fi
  
#  exec /usr/bin/chmod "${ORIG[@]}"
  echo "${ORIG[@]}"
}

main "$@"

exit 0
