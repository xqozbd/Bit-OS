#!/bin/sh
set -e

KERNEL=bitos
ISO=BitOS.iso

rm -rf iso_root "$ISO"

mkdir -p iso_root/boot/limine
mkdir -p iso_root/EFI/BOOT

# Kernel
cp -v bin/$KERNEL iso_root/boot/

# Limine config
cp -v limine.conf iso_root/boot/limine/

# Limine BIOS + UEFI files
cp -v \
  limine/limine-bios.sys \
  limine/limine-bios-cd.bin \
  limine/limine-uefi-cd.bin \
  iso_root/boot/limine/

# UEFI x86_64 loader
cp -v limine/BOOTX64.EFI iso_root/EFI/BOOT/

# Build ISO
xorriso -as mkisofs \
  -R -r -J \
  -b boot/limine/limine-bios-cd.bin \
  -no-emul-boot -boot-load-size 4 -boot-info-table \
  --efi-boot boot/limine/limine-uefi-cd.bin \
  -efi-boot-part --efi-boot-image --protective-msdos-label \
  iso_root -o "$ISO"

# Install Limine BIOS stage
./limine/limine bios-install "$ISO"

echo "ISO built: $ISO"
