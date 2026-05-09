readelf -r tomato.kpm | head -80
readelf -s tomato.kpm | grep -E 'kallsyms|hook|kver|cred|kpm|init|ctl|exit' | head -80
llvm-objdump -d --triple=aarch64-linux-gnu tomato.kpm | sed -n '1,120p'