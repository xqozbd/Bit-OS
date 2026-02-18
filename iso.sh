#!/bin/bash
set -e

KERNEL=bitos
ISO=BitOS.iso
INITRAMFS_DIR=initramfs
INITRAMFS_IMG=initramfs.cpio

rm -rf iso_root "$ISO"

mkdir -p iso_root/boot/limine
mkdir -p iso_root/EFI/BOOT

req_files="limine/limine-bios.sys limine/limine-bios-cd.bin limine/limine-uefi-cd.bin limine/BOOTX64.EFI"
for f in $req_files; do
  if [ ! -f "$f" ]; then
    echo "Missing Limine file: $f"
    echo "Place Limine release binaries in ./limine/ (limine-bios.sys, limine-bios-cd.bin, limine-uefi-cd.bin, BOOTX64.EFI)."
    exit 1
  fi
done

cp -v bin/$KERNEL iso_root/boot/

# Initramfs (optional)
if [ -d "$INITRAMFS_DIR" ]; then
  rm -rf "$INITRAMFS_DIR/bin"
  mkdir -p "$INITRAMFS_DIR/bin"
  mkdir -p "$INITRAMFS_DIR/lib"
  if [ -f "user/libu.c" ]; then
    x86_64-linux-gnu-gcc -nostdlib -shared -fPIC -Iuser \
      -Wl,-T,user/user_so.lds -Wl,-soname,libu.so \
      -o "$INITRAMFS_DIR/lib/libu.so" user/libu.c
  fi
  for src in user/init.c user/busybox.c; do
    [ -f "$src" ] || continue
    base=$(basename "$src" .c)
    x86_64-linux-gnu-gcc -nostdlib -static -ffreestanding -fno-pie -no-pie -Iuser \
      -Wl,-e,_start -Wl,-T,user/user.lds \
      -o "$INITRAMFS_DIR/bin/$base" "$src"
  done
  if [ -f "user/hello.c" ]; then
    x86_64-linux-gnu-gcc -nostdlib -ffreestanding -fPIE -pie -Iuser \
      -Wl,-e,_start -Wl,--no-as-needed -Wl,-rpath,/lib \
      -L"$INITRAMFS_DIR/lib" -Wl,-l:libu.so \
      -o "$INITRAMFS_DIR/bin/hello" user/hello.c
  fi
  if [ -f "$INITRAMFS_DIR/bin/busybox" ]; then
    for app in ls ps top mount umount dd; do
      ln -sf busybox "$INITRAMFS_DIR/bin/$app" 2>/dev/null || \
        cp -f "$INITRAMFS_DIR/bin/busybox" "$INITRAMFS_DIR/bin/$app"
    done
  fi
  mkdir -p "$INITRAMFS_DIR/etc"
  if [ ! -f "$INITRAMFS_DIR/etc/services.conf" ]; then
    cat > "$INITRAMFS_DIR/etc/services.conf" <<'EOF'
# name path after=<dependency>
ls /bin/ls
ps /bin/ps
top /bin/top after=ps
EOF
  fi
  (cd "$INITRAMFS_DIR" && find . -print0 | cpio --null -ov --format=newc) > "$INITRAMFS_IMG"
  cp -v "$INITRAMFS_IMG" iso_root/boot/
fi

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
if [ ! -x ./limine/limine ]; then
  echo "Limine BIOS installer not found, building..."
  (cd limine && make limine) || true
fi

if [ -x ./limine/limine ]; then
  ./limine/limine bios-install "$ISO"
else
  echo "Warning: ./limine/limine not available. BIOS install step skipped."
fi

echo "ISO built: $ISO"
