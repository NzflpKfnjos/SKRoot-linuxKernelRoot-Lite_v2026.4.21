#include "patch_kernel_root.h"
#include "analyze/base_func.h"
#include "analyze/symbol_analyze.h"
#include "patch_do_execve.h"
#include "patch_current_avc_check.h"
#include "patch_avc_denied.h"
#include "patch_audit_log_start.h"
#include "patch_filldir64.h"
#include "kpm_embed.h"

#include "3rdparty/find_mrs_register.h"
#include "3rdparty/find_imm_register_offset.h"
#include "3rdparty/find_adrp_target.h"

#include <algorithm>
#include <cctype>
#include <cstring>

struct PatchKernelOffset {
	size_t cred_offset = 0;
	size_t cred_uid_offset = 0;
	size_t seccomp_offset = 0;
	uint64_t huawei_kti_addr = 0;
};

struct PatchKernelResult {
	bool patched = false;
	size_t root_key_start = 0;
};

static void wait_before_exit() {
#ifdef _WIN32
	system("pause");
#endif
}

static size_t find_kernel_version_string_offset(const std::vector<char>& file_buf) {
	const char* prefix = "Linux version ";
	const size_t prefix_len = std::strlen(prefix);
	if (file_buf.size() < prefix_len) return 0;

	for (size_t i = 0; i + prefix_len < file_buf.size(); ++i) {
		if (std::memcmp(file_buf.data() + i, prefix, prefix_len) == 0 &&
			std::isdigit((unsigned char)file_buf[i + prefix_len])) {
			return i + prefix_len;
		}
	}
	return 0;
}

bool check_file_path(const char* file_path) {
	return std::filesystem::path(file_path).extension() != ".img";
}

bool parser_cred_offset(const std::vector<char>& file_buf, const SymbolRegion &symbol, size_t& cred_offset) {
	using namespace a64_find_mrs_register;
	std::vector<track_reg_info>track_info;
	if (!find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, track_info)) return false;
	cred_offset = 0;
	for (auto& t : track_info) {
		if (t.load_offset > 0x400) { cred_offset = t.load_offset; break; }
	}
	return cred_offset > 0;
}

bool parse_cred_uid_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, size_t cred_offset, size_t& cred_uid_offset) {
	using namespace a64_find_imm_register_offset;
	cred_uid_offset = 0;
	KernelVersionParser kernel_ver(file_buf);
	size_t min_off = 8;
	if (kernel_ver.is_kernel_version_less("6.6.8")) min_off = 4;

	std::vector<int64_t> candidate_offsets;
	if (!find_imm_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, candidate_offsets)) return false;

	auto it = std::find(candidate_offsets.begin(), candidate_offsets.end(), cred_offset);
	if (it != candidate_offsets.end()) {
		for (++it; it != candidate_offsets.end(); ++it) {
			if (*it > 0x20 || *it < min_off) continue;
			cred_uid_offset = *it;
			break;
		}
	}
	return cred_uid_offset != 0;
}

bool parser_seccomp_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, size_t& seccomp_offset) {
	using namespace a64_find_mrs_register;
	std::vector<track_reg_info>track_info;
	if (!find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, track_info)) return false;
	seccomp_offset = 0;
	for (auto& t : track_info) {
		if (t.load_offset > 0x400) { seccomp_offset = t.load_offset; break; }
	}
	return seccomp_offset > 0;
}

bool parser_huawei_kti_addr(const std::vector<char>& file_buf, const SymbolRegion& symbol, uint64_t& kti_addr) {
	using namespace a64_find_adrp_target;
	if (symbol.size == 0) return false;
	if (!find_adrp_target(file_buf, symbol.offset, symbol.offset + symbol.size, kti_addr)) return false;
	return kti_addr > 0;
}

static size_t align_up(size_t value, size_t align) {
	return (value + align - 1) & ~(align - 1);
}

struct ReservedRange {
	size_t begin = 0;
	size_t end = 0;
};

static void add_reserved_range(std::vector<ReservedRange>& ranges, size_t begin, size_t size) {
	if (!begin || !size) return;
	ranges.push_back({ begin, begin + size });
}

static void add_reserved_region(std::vector<ReservedRange>& ranges, const SymbolRegion& region) {
	add_reserved_range(ranges, static_cast<size_t>(region.offset), static_cast<size_t>(region.size));
}

static std::vector<ReservedRange> build_kpm_reserved_ranges(const KernelSymbolOffset& sym) {
	std::vector<ReservedRange> ranges;
	add_reserved_range(ranges, 0x200, 0x300);
	add_reserved_region(ranges, sym.die);
	add_reserved_region(ranges, sym.__drm_puts_coredump);
	add_reserved_region(ranges, sym.__drm_printfn_coredump);
	add_reserved_region(ranges, sym.__cfi_check);
	add_reserved_region(ranges, sym.__do_execve_file);
	add_reserved_region(ranges, sym.do_execveat_common);
	add_reserved_region(ranges, sym.do_execve_common);
	add_reserved_region(ranges, sym.do_execveat);
	add_reserved_region(ranges, sym.do_execve);
	add_reserved_region(ranges, sym.avc_denied);
	add_reserved_range(ranges, sym.audit_log_start, 4);
	add_reserved_range(ranges, sym.filldir64, 4);
	add_reserved_range(ranges, sym.__cfi_check_fail, 4);
	add_reserved_range(ranges, sym.__cfi_slowpath_diag, 4);
	add_reserved_range(ranges, sym.__cfi_slowpath, 4);
	add_reserved_range(ranges, sym.__ubsan_handle_cfi_check_fail_abort, 4);
	add_reserved_range(ranges, sym.__ubsan_handle_cfi_check_fail, 4);
	add_reserved_range(ranges, sym.report_cfi_failure, 4);
	add_reserved_range(ranges, sym.hkip_check_uid_root, 4);
	add_reserved_range(ranges, sym.hkip_check_gid_root, 4);
	add_reserved_range(ranges, sym.hkip_check_xid_root, 4);
	return ranges;
}

static void consider_zero_cave_segment(size_t segment_start, size_t segment_end, size_t min_size, SymbolRegion& best) {
	size_t aligned_start = align_up(segment_start, 16);
	if (aligned_start >= segment_end) return;
	size_t aligned_size = segment_end - aligned_start;
	if (aligned_size >= min_size && aligned_size > best.size) {
		best = { aligned_start, aligned_size };
	}
}

static SymbolRegion find_zero_code_cave(const std::vector<char>& file_buf, size_t begin, size_t end, size_t min_size,
	const std::vector<ReservedRange>& reserved_ranges = {}) {
	SymbolRegion best = { 0, 0 };
	if (begin >= file_buf.size()) return best;
	end = std::min(end, file_buf.size());
	if (begin >= end) return best;

	std::vector<ReservedRange> ranges = reserved_ranges;
	std::sort(ranges.begin(), ranges.end(), [](const ReservedRange& a, const ReservedRange& b) {
		return a.begin < b.begin;
	});

	size_t i = begin;
	while (i < end) {
		while (i < end && file_buf[i] != 0) ++i;
		size_t run_start = i;
		while (i < end && file_buf[i] == 0) ++i;
		size_t run_end = i;
		size_t segment_start = run_start;

		for (const auto& range : ranges) {
			if (range.end <= segment_start) continue;
			if (range.begin >= run_end) break;
			if (range.begin > segment_start) {
				consider_zero_cave_segment(segment_start, std::min(range.begin, run_end), min_size, best);
			}
			segment_start = std::max(segment_start, range.end);
			if (segment_start >= run_end) break;
		}
		consider_zero_cave_segment(segment_start, run_end, min_size, best);
	}
	return best;
}

void cfi_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	if (sym.__cfi_check.offset) PATCH_AND_CONSUME(sym.__cfi_check, patch_ret_cmd(file_buf, sym.__cfi_check.offset, vec_patch_bytes_data));
	patch_ret_cmd(file_buf, sym.__cfi_check_fail, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__cfi_slowpath_diag, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__cfi_slowpath, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail_abort, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail, vec_patch_bytes_data);
	patch_ret_1_cmd(file_buf, sym.report_cfi_failure, vec_patch_bytes_data);
}

void huawei_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	patch_ret_0_cmd(file_buf, sym.hkip_check_uid_root, vec_patch_bytes_data);
	patch_ret_0_cmd(file_buf, sym.hkip_check_gid_root, vec_patch_bytes_data);
	patch_ret_0_cmd(file_buf, sym.hkip_check_xid_root, vec_patch_bytes_data);
}

PatchKernelResult patch_kernel_handler(const std::vector<char>& file_buf, const PatchKernelOffset& off, KernelSymbolOffset& sym, std::vector<patch_bytes_data>& vec_patch_bytes_data, size_t kpm_handler_addr = 0) {
	KernelVersionParser kernel_ver(file_buf);
	PatchBase patchBase(file_buf, off.cred_uid_offset, { .kti_addr = off.huawei_kti_addr });
	PatchDoExecve patchDoExecve(patchBase, sym);
	PatchCurrentAvcCheck patchCurrentAvcCheck(patchBase);
	PatchAvcDenied patchAvcDenied(patchBase, sym.avc_denied);
	PatchAuditLogStart patchAuditLogStart(patchBase, sym.audit_log_start);
	PatchFilldir64 patchFilldir64(patchBase, sym.filldir64);

	bool patched = true;
	PatchKernelResult r;
	if (kernel_ver.is_kernel_version_less("6.1.0")) {
		SymbolRegion next_empty_region = { 0x200, 0x300 };
		if (sym.__cfi_check.offset && sym.__cfi_check.size > next_empty_region.size) next_empty_region = sym.__cfi_check;
		auto start_b_location = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, 4);
		r.root_key_start = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, patchDoExecve.patch_do_execve(next_empty_region, off.cred_offset, off.seccomp_offset, vec_patch_bytes_data, kpm_handler_addr));
		PATCH_AND_CONSUME(next_empty_region, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, next_empty_region, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchFilldir64.patch_filldir64_core(next_empty_region, vec_patch_bytes_data));
		auto current_avc_check_bl_func = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, patchCurrentAvcCheck.patch_current_avc_check_bl_func(next_empty_region, off.cred_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchAvcDenied.patch_avc_denied(next_empty_region, current_avc_check_bl_func, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchAuditLogStart.patch_audit_log_start(next_empty_region, current_avc_check_bl_func, vec_patch_bytes_data));
		auto end_b_location = next_empty_region.offset;
		patchBase.patch_jump(start_b_location, end_b_location, vec_patch_bytes_data);
	} else if (sym.die.offset && sym.__drm_puts_coredump.offset && sym.__drm_printfn_coredump.offset) {
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patch_ret_cmd(file_buf, sym.__drm_printfn_coredump.offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_puts_coredump, patch_ret_cmd(file_buf, sym.__drm_puts_coredump.offset, vec_patch_bytes_data));
		r.root_key_start = sym.die.offset;
		PATCH_AND_CONSUME(sym.die, patchDoExecve.patch_do_execve(sym.die, off.cred_offset, off.seccomp_offset, vec_patch_bytes_data, kpm_handler_addr));
		PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, sym.die, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_jump(sym.die.offset, sym.__drm_puts_coredump.offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_puts_coredump, patchFilldir64.patch_filldir64_core(sym.__drm_puts_coredump, vec_patch_bytes_data));
		auto current_avc_check_bl_func = sym.__drm_printfn_coredump.offset;
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchCurrentAvcCheck.patch_current_avc_check_bl_func(sym.__drm_printfn_coredump, off.cred_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAvcDenied.patch_avc_denied(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAuditLogStart.patch_audit_log_start(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
	} else {
		patched = false;
	}
	r.patched = patched;
	return r;
}

void write_all_patch(const char* file_path, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	for (auto& item : vec_patch_bytes_data) {
		std::shared_ptr<char> spData(new (std::nothrow) char[item.str_bytes.length() / 2], std::default_delete<char[]>());
		hex2bytes((uint8_t*)item.str_bytes.c_str(), (uint8_t*)spData.get());
		if (!write_file_bytes(file_path, item.write_addr, spData.get(), item.str_bytes.length() / 2)) {
			std::cout << "写入文件发生错误" << std::endl;
		}
	}
	if (vec_patch_bytes_data.size()) std::cout << "Done." << std::endl;
}

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	std::cout << "本工具用于生成SKRoot(Lite) ARM64 Linux内核ROOT提权代码 V12" << std::endl << std::endl;

#ifdef _DEBUG
#else
	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		wait_before_exit();
		return 0;
	}
#endif

#ifdef _DEBUG
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\kernel_dump)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\Xiaomi11_V14.0.11.0.TKACNXM.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\hm7.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\6.1.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\9pro6.1.90.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\269.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\android15-6.6.30_2024-08-boot.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\9pro.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\boot11.104img\boot11.104img)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\1)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\Image)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\vmlinux)***";
	//const char* file_path = R"***(C:\Users\maily\5.15.119.img-kernel\k20.img-kernel)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\boot_huwei_4.114.104img)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\aaa.img-kernel)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\mi8v10)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\5.15.119.img-kernel)***";
	const char* file_path = R"***(C:\Users\maily\Desktop\mi6max)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\skr_fix_6s\o.img-kernel)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\mi6max)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\ry)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\6.12小米17kernel)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\Image-ares-202508111948\Image)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\测试内核\mi6max)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\测试内核\k20.img-kernel)***";
	//const char* file_path = R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\boot11k40\boot11k40)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\4.4.2234.4.223\split_img\boot.img-kernel)***";
	//const char* file_path = R"***(C:\Users\maily\Desktop\机型一加15，内核6.12.23)***";
#else
	const char* file_path = argv[0];
#endif
	std::cout << file_path << std::endl << std::endl;
	if (!check_file_path(file_path)) {
		std::cout << "Please enter the correct Linux kernel binary file path. " << std::endl;
		std::cout << "For example, if it is boot.img, you need to first decompress boot.img and then extract the kernel file inside." << std::endl;
		wait_before_exit();
		return 0;
	}

	std::vector<char> file_buf = read_file_buf(file_path);
	if (!file_buf.size()) {
		std::cout << "Fail to open file:" << file_path << std::endl;
		wait_before_exit();
		return 0;
	}

	SymbolAnalyze symbol_analyze(file_buf);
	if (!symbol_analyze.analyze_kernel_symbol()) {
		std::cout << "Failed to analyze kernel symbols" << std::endl;
		wait_before_exit();
		return 0;
	}
	KernelSymbolOffset sym = symbol_analyze.get_symbol_offset();
	uint64_t anchor_off = sym.die.offset;

	PatchKernelOffset off;
	if (!parser_cred_offset(file_buf, sym.sys_getuid, off.cred_offset)) {
		std::cout << "Failed to parse cred offset" << std::endl;
		wait_before_exit();
		return 0;
	}

	if (!parse_cred_uid_offset(file_buf, sym.sys_getuid, off.cred_offset, off.cred_uid_offset)) {
		std::cout << "Failed to parse cred uid offset" << std::endl;
		wait_before_exit();
		return 0;
	}
	std::cout << "cred uid offset:" << off.cred_uid_offset << std::endl;

	if (!parser_seccomp_offset(file_buf, sym.prctl_get_seccomp, off.seccomp_offset)) {
		std::cout << "Failed to parse seccomp offset" << std::endl;
		wait_before_exit();
		return 0;
	}
	std::cout << "cred offset:" << off.cred_offset << std::endl;
	std::cout << "seccomp offset:" << off.seccomp_offset << std::endl;

	parser_huawei_kti_addr(file_buf, sym.kti_randomize_init, off.huawei_kti_addr);
	if(off.huawei_kti_addr) std::cout << "kti addr:" << off.huawei_kti_addr << std::endl;

	std::vector<patch_bytes_data> vec_patch_bytes_data;
	cfi_bypass(file_buf, sym, vec_patch_bytes_data);
	huawei_bypass(file_buf, sym, vec_patch_bytes_data);

	/* === KPM Loader Integration === */
	size_t kpm_handler_addr = 0;
	{
		KernelSymbolParser sym_parser(file_buf);
		sym_parser.init_kallsyms_lookup_name();
		uint64_t _km_addr = sym_parser.kallsyms_lookup_name("__kmalloc");
		if (!_km_addr) _km_addr = sym_parser.kallsyms_lookup_name("kmalloc");
		uint64_t _kf_addr = sym_parser.kallsyms_lookup_name("kfree");
		uint64_t _pk_addr = sym_parser.kallsyms_lookup_name("printk");
		if (!_pk_addr) _pk_addr = sym_parser.kallsyms_lookup_name("_printk");

		if (_km_addr && _kf_addr && _pk_addr) {
			uint64_t _vm_addr = sym_parser.kallsyms_lookup_name("vmalloc");
			if (!_vm_addr) _vm_addr = sym_parser.kallsyms_lookup_name("__vmalloc");
			uint64_t _vf_addr = sym_parser.kallsyms_lookup_name("vfree");
			uint64_t _ms_addr = sym_parser.kallsyms_lookup_name("memset");
			uint64_t _mc_addr = sym_parser.kallsyms_lookup_name("memcpy");
			uint64_t _sct_addr = sym_parser.kallsyms_lookup_name("sys_call_table");
			uint64_t _kln_addr = sym_parser.kallsyms_lookup_name("kallsyms_lookup_name");
			uint64_t _it_addr = sym_parser.kallsyms_lookup_name("init_task");
			uint64_t _fo_addr = sym_parser.kallsyms_lookup_name("filp_open");
			uint64_t _kr_addr = sym_parser.kallsyms_lookup_name("kernel_read");
			if (!_kr_addr) _kr_addr = sym_parser.kallsyms_lookup_name("__kernel_read");
			uint64_t _fc_addr = sym_parser.kallsyms_lookup_name("filp_close");
			uint64_t _cfu_addr = sym_parser.kallsyms_lookup_name("_copy_from_user");
			if (!_cfu_addr) _cfu_addr = sym_parser.kallsyms_lookup_name("copy_from_user");
			if (!_cfu_addr) _cfu_addr = sym_parser.kallsyms_lookup_name("__arch_copy_from_user");

			std::cout << std::endl << "=== KPM Loader Integration ===" << std::endl;

			std::vector<ReservedRange> kpm_reserved_ranges = build_kpm_reserved_ranges(sym);
				SymbolRegion kpm_region = find_zero_code_cave(file_buf, sym._stext ? sym._stext : 0x10000, sym._etext ? sym._etext : file_buf.size(), kpm_required_space(), kpm_reserved_ranges);
				if (kpm_region.valid()) {
					std::cout << "KPM code cave: 0x" << std::hex << kpm_region.offset
						<< ", size:0x" << kpm_region.size << std::endl;
				}

			if (kpm_region.valid() && kpm_region.size >= kpm_required_space()) {
				KpmEmbedConfig kcfg{};
				kcfg.kernel_file_buf = &file_buf;
				kcfg.cred_offset = off.cred_offset;
				kcfg.cred_uid_offset = off.cred_uid_offset;
				kcfg.seccomp_offset = off.seccomp_offset;

				PatchBase tmpBase(file_buf, off.cred_uid_offset,
					{ .kti_addr = off.huawei_kti_addr });
				kcfg.thread_info_in_task = tmpBase.is_CONFIG_THREAD_INFO_IN_TASK();
				kcfg.sp_el0_is_current = kcfg.thread_info_in_task;
				kcfg.sp_el0_is_thread_info = tmpBase.is_CURRENT_FROM_SP_EL0_THREAD_INFO();

				KernelVersionParser kvp(file_buf);
				kcfg.has_syscall_wrapper = !kvp.is_kernel_version_less("4.17.0");
				PatchDoExecve tmpDoExecve(tmpBase, sym);
				kcfg.execve_filename_reg = tmpDoExecve.get_execve_filename_reg();
				kcfg.execve_filename_is_direct = tmpDoExecve.is_execve_filename_direct();
				kcfg.kernel_version_str = (const char*)find_kernel_version_string_offset(file_buf);
				kcfg.kallsyms_lookup_name_addr = _kln_addr;
					if (!_kln_addr) {
						std::cout << "[WARNING] kallsyms_lookup_name not resolved; KPM external symbols will fail-fast" << std::endl;
					}
				kcfg.kernel_va_base = sym_parser.kernel_base();
				if (kcfg.kernel_va_base) {
					std::cout << "kernel VA base: 0x" << std::hex << kcfg.kernel_va_base << std::endl;
				}
				kcfg.kmalloc_addr = _km_addr;
				kcfg.kfree_addr = _kf_addr;
				kcfg.vmalloc_addr = _vm_addr;
				kcfg.vfree_addr = _vf_addr;
				kcfg.memset_addr = _ms_addr;
				kcfg.memcpy_addr = _mc_addr;
				kcfg.printk_addr = _pk_addr;
				kcfg.syscall_table_addr = _sct_addr;
				kcfg.init_task_addr = _it_addr;
				kcfg.filp_open_addr = _fo_addr;
				kcfg.kernel_read_addr = _kr_addr;
				kcfg.filp_close_addr = _fc_addr;
				kcfg.copy_from_user_addr = _cfu_addr;
				kcfg.kti_addr = off.huawei_kti_addr;

				KpmEmbedResult kr = kpm_embed_loader(kcfg, kpm_region);
				if (kr.success) {
					for (auto& p : kr.patches)
						vec_patch_bytes_data.push_back(p);
					kpm_handler_addr = kr.command_handler_addr;
					std::cout << "KPM handler: 0x" << std::hex
						<< kr.command_handler_addr << std::endl;
				}
			} else {
				std::cout << "[WARN] Not enough kernel space for KPM loader" << std::endl;
			}
		} else {
			std::cout << "[WARN] KPM loader skipped: missing kernel API symbols" << std::endl;
		}
	}

	size_t first_hook_start = 0;
	PatchKernelResult pr = patch_kernel_handler(file_buf, off, sym, vec_patch_bytes_data, kpm_handler_addr);
	if (!pr.patched) {
		std::cout << "Failed to find hook start addr" << std::endl;
		wait_before_exit();
		return 0;
	}

	std::string str_root_key;
	size_t is_need_create_root_key = 0;
	std::cout << std::endl << "请选择是否需要自动随机生成ROOT密匙（1需要；2不需要）：" << std::endl;
	if (!(std::cin >> std::dec >> is_need_create_root_key)) {
		std::cout << "输入已结束，未写入文件。" << std::endl;
		wait_before_exit();
		return 1;
	}
	if (is_need_create_root_key == 1) {
		str_root_key = generate_random_str(ROOT_KEY_LEN);
	} else {
		std::cout << "请输入ROOT密匙（48个字符的字符串，包含大小写和数字）：" << std::endl;
		if (!(std::cin >> str_root_key) || str_root_key.empty()) {
			std::cout << "ROOT 密匙为空，未写入文件。" << std::endl;
			wait_before_exit();
			return 1;
		}
		std::cout << std::endl;
	}
	std::string write_key = str_root_key;
	write_key.erase(write_key.size() - 1);
	patch_data(file_buf, pr.root_key_start, (void*)write_key.c_str(), write_key.length() + 1, vec_patch_bytes_data);

	std::cout << "#获取ROOT权限的密匙(Key): " << str_root_key.c_str() << std::endl << std::endl;

	size_t need_write_modify_in_file = 0;
	std::cout << "#是否需要立即写入修改到文件？（1需要；2不需要）：" << std::endl;
	if (!(std::cin >> need_write_modify_in_file)) {
		std::cout << "输入已结束，未写入文件。" << std::endl;
		wait_before_exit();
		return 1;
	}
	if (need_write_modify_in_file == 1) {
		std::cout << "#正在写入，请稍后..." << std::endl;
		write_all_patch(file_path, vec_patch_bytes_data);
	}
	wait_before_exit();
	return 0;
}
