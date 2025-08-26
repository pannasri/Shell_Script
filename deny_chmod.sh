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


# -------------------------
# "/" 또는 "/등등" (루트 바로 하위)인지 검사
# -------------------------

is_root_or_immediate_child() {
  local p="$1"
  [[ "$p" == "/" || "$p" =~ ^/[^/]+/?$ ]] && return 0
}


# -------------------------
# BLOCKED_PATHS 배열에 포함되는지 검사
# -------------------------

is_in_blocklist() {
  local p="$1" b
  for b in "${BLOCKED_PATHS[@]}";do
    [[ "$p" == "$b" || "$p" == "$b"/ ]] && return 0
  done
  return 1
}


# -------------------------
# 모드 및 파일 추출
# -------------------------

extract_mode_and_files() {
  local args=( "$@" ); new_args=()

  for a in "${args[@]}";do
    ## 숫자 모드
    [[ $a =~ ^[+-=]?0*[0-7]{3,4}$ ]] && MODE="$a" && continue
    ## 심볼릭 모드
    [[ $a =~ ^([ugoa]*[+-=]([rwxXst]+|[ugo]))(,[ugoa]*[+-=]([rwxXst]+|[ugo]))*$ ]] && MODE="$a" && continue
    new_args+=("$a")
  done

  local short_opts=Rvcf
  local long_opts=changes,silent,quiet,verbose,no-preserve-root,preserve-root,reference:,recursive,help,version
  local parsed getopt_ec

  parsed=$(getopt -s bash -o "$short_opts" -l "$long_opts" -n "chmod_wrapper" -- "${new_args[@]}")

  getopt_ec=$?

  if [[ $getopt_ec -ne 0 ]];then
    die "Failed to parse options"; return $?
  fi

  eval set -- "$parsed"

  ## reference 및 recursive 확인
  while (( $# ));do
    case "$1" in
      --) shift; break ;;
      --reference) REF_MODE=1; shift;
                     (($#)) || break
                   REF_FILE="$1"
                   shift; continue ;;
      -R|--recursive) USE_R=1; shift; continue ;;
      --help|--version) exec -a chmod "$CHMOD_REAL" "$1"; E_CODE=1; break ;;
      *) shift; continue ;;
    esac
  done
  FILES=( "$@" )
}


# -------------------------
# 777 확인
# -------------------------

# 모드 수정 파일 권한 확인
deny_exec_risk_propagation() {
  local file="$1" who=$2 op=$3 perms=$4
  local file_mode="$(stat -c "%a" "$file")" om
  om=$(( 8#${file_mode#0} ))

  ## X 옵션 체크
  if [[ $op =~ [-+=] && $perms == *X* && $perms == *r* && $perms == *w* ]];then
    [[ $who == *a* || $who =~ [ugo]{3} ]] || return 1
    if (( (om & 0111) ));then
      return 0
    fi
  fi

  ## 특정 비트 권한 수여 체크
  if [[ ( $who == *a* || $who =~ ^[ugo]{2,3}+$ ) && $perms =~ ^[ugo]$ ]];then

    case $perms in
      u) [[ $who == *a* || ($who == *g* && $who == *o*) ]] && (( ((om >> 6) & 7 ) == 7 )) && return 0 ;;
      g) [[ $who == *a* || ($who == *u* && $who == *o*) ]] && (( ((om >> 3) & 7 ) == 7 )) && return 0 ;;
      o) [[ $who == *a* || ($who == *g* && $who == *u*) ]] && (( ((om >> 0) & 7 ) == 7 )) && return 0 ;;
      *) die "chmod: invalid mode: $who$op$perms\nTry 'chmod --help' for more information." ;;
    esac
  fi
  return 1
}

# 777 확인
is_dangerous_777() {
  local m="$1" f="${2:-}" seg who op perms
  ## 숫자 모드 777 점검
  [[ "$m" =~ ^[-+=]?(0*|[1-7])777$ ]] && return 0

  ## 심볼릭 모드 777 점검
  IFS=',' read -r -a _segs <<< "$m"
  seg_re='^([ugoa]*)([+=-])([rwxXst]+|[ugo])$'
  for seg in "${_segs[@]}";do
    [[ $seg =~ $seg_re ]] || continue
    who="${BASH_REMATCH[1]:-a}"
    op="${BASH_REMATCH[2]}"
    perms="${BASH_REMATCH[3]}"
    if [[ $who == a || $who =~ [ugo]{3} ]];then
      [[ $perms == *r* && $perms == *w* && $perms == *x* && $perms =~ ^[rwxstX]{3,6}$ ]] && return 0
    fi
    if [[ $USE_R == 0 ]];then
      if deny_exec_risk_propagation "$f" "$who" "$op" "$perms";then
        return 0
      fi
    fi
  done
  return 1
}


# -------------------------
# Main 함수
# -------------------------

main() {
  local ORIG=( "$@" )
  local CHMOD_REAL=${CHMOD_REAL:-/usr/libexec/chmod.org}
  local MODE=""; REF_MODE=0; FILES=(); REF_FILE=""; USE_R=0; E_CODE=0

  extract_mode_and_files "${ORIG[@]}" || return $?
  [[ "$E_CODE" == 0 ]] || return 0

  (( ${#FILES[@]} > 0 )) || { die "chmod: missing operand for '대상을 찾을 수 없음'\nTry 'chmod --help' for more information."; return $?; }

  local f canon_f
  for f in "${FILES[@]}";do
    [[ "$f" == -* ]] && continue

    canon_f="$(readlink -f -- "$f")" || die "chmod: cannot access '"$f"': No such file or directory"
    if is_root_or_immediate_child "$canon_f" || is_in_blocklist "$canon_f";then
      die "해당 경로는 권한 변경이 불가능합니다."
    fi
  done

  if [[ "$USE_R" == 1 ]];then
    die "-R/--recursive 는 정책 상 막혀있습니다."
  fi


  if (( REF_MODE == 0 )) && [[ -n "${MODE:-}" ]] && is_dangerous_777 "$MODE" "$canon_f";then 
    die "chmod 777 은 막혔습니다."
  fi
  
  if (( REF_MODE == 1 )) && [[ -n ${REF_FILE:-} ]];then
    local ref_mode
    ref_mode=$(stat -c %a -- "$REF_FILE" 2>/dev/null || printf '')
    if [[ $ref_mode =~ ^[0-7]{3,4}$ ]] && is_dangerous_777 "$ref_mode"; then
      die "chmod 777 은 막혔습니다."
    fi
  fi

  if ! grep -wq -- '--preserve-root' <<< "${ORIG[@]}";then
    exec -a chmod "$CHMOD_REAL" --preserve-root "${ORIG[@]}"
  else
    exec -a chmod "$CHMOD_REAL" "${ORIG[@]}"
  fi
}

main "$@"

exit 0
