set -e
cd Lite_version/src/patch_kernel_root
printf '2\nMoFS20amQM1zKk0pa7ZHuBm4rMaiapAlVWoxVCwdSSD4PlkX\n1\n' | ./patch_kernel_root ../../../boot_build_kpm_pagealign_fix/kernel | tee ../../../boot_build_kpm_pagealign_fix/patch.log