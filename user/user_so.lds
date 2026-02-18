OUTPUT_FORMAT(elf64-x86-64)

SECTIONS
{
    /DISCARD/ : {
        *(.note.gnu.property)
        *(.note.gnu.build-id)
        *(.note .note.*)
        *(.eh_frame*)
    }

    . = 0x0;

    .text : {
        *(.text .text.*)
    }

    .plt : { *(.plt .plt.*) }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .got : { *(.got .got.*) }
    .got.plt : { *(.got.plt .got.plt.*) }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    .dynamic : { *(.dynamic) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }
    .rela.dyn : { *(.rela.dyn) }
    .rela.plt : { *(.rela.plt) }
    .rel.dyn : { *(.rel.dyn) }
    .rel.plt : { *(.rel.plt) }
}
