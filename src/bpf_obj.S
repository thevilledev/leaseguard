/* SPDX-License-Identifier: MIT */
/* Embeds the compiled datapath; LG_BPF_OBJ is its path, set by the Makefile. */
	.section .rodata
	.balign 8
	.global lg_bpf_obj
lg_bpf_obj:
	.incbin LG_BPF_OBJ
	.global lg_bpf_obj_end
lg_bpf_obj_end:
	.section .note.GNU-stack, "", %progbits
