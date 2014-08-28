#match multiple lines. watch the white space before nc
# nc -4 -l 192.1.2.23 222 &
#[1] 2209
/^ nc .*\&/ {N; s/^ nc \(.*\&\)\n\[[0-9]*\] [0-9]*$/ nc \1/g}
