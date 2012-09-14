# add swan test binaries to path

case ":${PATH:-}:" in
    *:/testing/scripts/guestbin:*) ;;
    *) PATH="/testing/scripts/guestbin${PATH:+:$PATH}" ;;
esac


