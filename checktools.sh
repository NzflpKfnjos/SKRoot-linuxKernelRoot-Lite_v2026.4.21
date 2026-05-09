for c in clang gcc g++ make python3 xxd ld.lld file readelf llvm-readelf; do
  printf "%s=" "$c"
  command -v "$c" || true
done