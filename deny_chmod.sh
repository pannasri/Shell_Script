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

die() { printf '%s\n' "$*" >&2; exit 1; }


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
    [[ $m == *r* && $m == *w* && $m == *x* && $m = *X* ]] && return 0
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

  (( ${#FILES[@]} > 0 )) || die "chmod: missing operand"

  local f
  for f in "${FILES[@]}";do
    [[ "$f" == -* ]] && continue
    if is_root_or_immediate_child "$f" || is_in_blocklist "$f";then
      die "해당 경로는 권한 변경이 불가능합니다."
    fi
  done

  if contains_recursive "${ORIG[@]}";then
    die "-R/--recursive 는 정책 상 막혀있습니다."
  fi


  if (( REF_MODE == 0 )) && [[ -n "${MODE:-}" ]] && is_dangerous_777 "$MODE";then
    die "chmod 777 은 막혔습니다."
  fi
  
  exec /usr/bin/chmod "${ORIG[@]}"
}

main "$@"

exit 0
