# flterm

Tool for loading data over serial.

It seems to work well with really crappy / partially working serial ports.

Allows firmware to be loaded onto the soft-CPU found inside
[MiSoC](https://github.com/m-labs/misoc) or
[LiteX](https://github.com/enjoy-digital/litex) FPGA SoCs.

```
Serial boot program for MiSoC - v. 2.4
Copyright (C) 2007, 2008, 2009, 2010, 2011 Sebastien Bourdeauducq
Copyright (C) 2011 Michael Walle
Copyright (C) 2004 MontaVista Software, Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

Usage: flterm --port <port>
              [--speed <speed>] [--gdb-passthrough] [--debug]
              [--kernel <kernel_image> [--kernel-adr <address>]]
              [--cmdline <cmdline> [--cmdline-adr <address>]]
              [--initrd <initrd_image> [--initrd-adr <address>]]
              [--log <log_file>]

Default load addresses:
  kernel:  0x40000000
  cmdline: 0x41000000
  initrd:  0x41002000
```

# License

flterm is released under the
[GPLv3.0 license](https://www.gnu.org/licenses/gpl-3.0.en.html)
