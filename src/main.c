/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <elf.h>
#include <string.h>

int get_section(int fd, int shtype, Elf64_Shdr* shdr);
char* find_symbol_entry(int fd, Elf64_Shdr shdr, uintptr_t addr, char* name, int name_sz);
char* symbol_name(int fd, uintptr_t addr, char* name, int name_sz);
unsigned long int read_leb128(int fd, int* length, int sign);
int size_of_encoded_value(int encoding);
uintptr_t get_encoded_value(int fd, int encoding);
int read_dwarf2(int fd);

static int opt_csv = 0;
static int opt_dec = 0;

int get_section(int fd, int shtype, Elf64_Shdr* shdr)
{
    if (fd < 0 || !shdr)
        return -1;

    int saved_pos = lseek(fd, 0, SEEK_CUR);
    int found_it = 0;

    Elf64_Ehdr ehdr;
    lseek(fd, 0, SEEK_SET);
    read(fd, (char*) &ehdr, sizeof(Elf64_Ehdr));

    for (int i = 0; i < ehdr.e_shnum; ++i)
    {
        // Get this section header
        lseek(fd, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
        read(fd, (char*) shdr, sizeof(Elf64_Shdr));

        // We want the symtab
        if ((int) shdr->sh_type == shtype)
        {
            found_it = 1;
            break;
        }
    }

    lseek(fd, saved_pos, SEEK_SET);
    return found_it ? 0 : -1;
}

char* find_symbol_entry(int fd, Elf64_Shdr shdr, uintptr_t addr, char* name, int name_sz)
{
    if (fd < 0)
        return 0;

    int saved_pos = lseek(fd, 0, SEEK_CUR);
    int found_it = 0;

    Elf64_Ehdr ehdr;
    lseek(fd, 0, SEEK_SET);
    read(fd, (char*) &ehdr, sizeof(Elf64_Ehdr));

    // Save offset and number of entries
    int symtab_offset = shdr.sh_offset;
    int symtab_num = (int) (shdr.sh_size / sizeof(Elf64_Sym));
    int symtab_link = shdr.sh_link;

    // Read linked .strtab
    lseek(fd, ehdr.e_shoff + symtab_link * sizeof(Elf64_Shdr), SEEK_SET);
    read(fd, (char*) &shdr, sizeof(Elf64_Shdr));

    // Save strtab offset
    int strtab_offset = shdr.sh_offset;

    // Iterate over all symbols
    for (int j = 0; j < symtab_num; ++j)
    {
        // Get the symbol from file
        Elf64_Sym sym;
        lseek(fd, symtab_offset + j * sizeof(Elf64_Sym), SEEK_SET);
        read(fd, (char*) &sym, sizeof(Elf64_Sym));

        // Ignore unnamed entries
        if (sym.st_name == SHN_UNDEF)
            continue;

        if (sym.st_value != addr)
            continue;

        // Get its name
        lseek(fd, strtab_offset + sym.st_name, SEEK_SET);
        read(fd, name, name_sz);

        found_it = 1;
        break;
    }

    lseek(fd, saved_pos, SEEK_SET);

    return found_it ? name : 0;
}

//! Get the name of a symbol, given its address
char* symbol_name(int fd, uintptr_t addr, char* name, int name_sz)
{
    if (fd < 0 || !name)
        return 0;

    int saved_pos = lseek(fd, 0, SEEK_CUR);
    int found_it = 0;

    Elf64_Shdr shdr;
    if (get_section(fd, SHT_SYMTAB, &shdr) == 0 &&
        find_symbol_entry(fd, shdr, addr, name, name_sz))
    {
        found_it = 1;
    }
    else if (get_section(fd, SHT_DYNSYM, &shdr) == 0 &&
        find_symbol_entry(fd, shdr, addr, name, name_sz))
    {
        found_it = 1;
    }

    lseek(fd, saved_pos, SEEK_SET);

    return found_it ? name : 0;
}

unsigned long int read_leb128(int fd, int* length, int sign)
{
    unsigned long int result = 0;
    int num_read = 0;
    unsigned int shift = 0;
    unsigned char byte;

    do
    {
        read(fd, (char*) &byte, 1);
        ++num_read;

        result |= ((unsigned long int) (byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if (length)
        *length = num_read;

    if (sign && (shift < 8 * sizeof(result)) && (byte & 0x40))
        result |= -1L << shift;

    return result;
}

int size_of_encoded_value(int encoding)
{
    switch (encoding & 0x7)
    {
        default: /* ??? */
        case 0: return sizeof(void*);
        case 2: return 2;
        case 3: return 4;
        case 4: return 8;
    }
}

uintptr_t get_encoded_value(int fd, int encoding)
{
    uintptr_t x = 0;

    int size = size_of_encoded_value(encoding);
    read(fd, (char*) &x, size);

    if (encoding & 0x09 /* 0x08 */)
    {
        switch (size)
        {
            case 1:
                return (x ^ 0x80) - 0x80;
            case 2:
                return (x ^ 0x8000) - 0x8000;
            case 4:
                return (x ^ 0x80000000) - 0x80000000;
            case 8:
                return x;
            default:
                return 0;
        }
    }

    return x;
}

int read_dwarf2(int fd)
{
    if (fd < 0)
        return -1;

    Elf64_Ehdr ehdr;
    lseek(fd, 0, SEEK_SET);
    read(fd, (char*) &ehdr, sizeof(Elf64_Ehdr));

    // You have to read how readelf --debug-dump=frames works to understand
    //   the code below.
    // https://opensource.apple.com/source/gdb/gdb-961/src/binutils/readelf.c
    // We analyze the contents of the .eh_frame section (that is always present)
    //   in the DWARF2 format, in order to retrieve a list of function addresses
    //   and sizes.

    Elf64_Shdr shstrtab;
    lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    read(fd, (char*) &shstrtab, sizeof(Elf64_Shdr));

    for (int i = 0; i < ehdr.e_shnum; ++i)
    {
        // Get this section header
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
        read(fd, (char*) &shdr, sizeof(Elf64_Shdr));

        // Read in its name
        char name[128];
        lseek(fd, shstrtab.sh_offset + shdr.sh_name, SEEK_SET);
        read(fd, &name[0], sizeof(name));

        if (strcmp(&name[0], ".eh_frame"))
            continue;

        int ptr_encoding = 0;
        int encoded_ptr_size = sizeof(void*);

        for (int off = 0; off < (int) shdr.sh_size; )
        {
            lseek(fd, shdr.sh_offset + off, SEEK_SET);

            uint64_t length = 0;
            read(fd, (char*) &length, sizeof(uint32_t));

            if (length == 0)
            {
                // nul terminator
                break;
            }

            int off_size;
            int initial_size;

            if (length == 0xFFFFFFFF)
            {
                read(fd, (char*) &length, sizeof(length));
                off_size = sizeof(uint64_t);
                initial_size = sizeof(uint32_t) + sizeof(uint64_t);
            }
            else
            {
                off_size = sizeof(uint32_t);
                initial_size = sizeof(uint32_t);
            }

            int block_end = off + initial_size + length;

            uint64_t cie_id = 0;
            read(fd, (char*) &cie_id, off_size);

            if (!cie_id)
            {
                // Read in version
                int version = 0;
                read(fd, (char*) &version, 1);

                // Read in the augmentation string
                char aug[32];
                read(fd, &aug[0], sizeof(aug));
                int aug_len = strlen(&aug[0]) + 1;

                // Seek to the end of the augmentation string, as we have
                //   read sizeof(aug) bytes blindly
                lseek(fd, shdr.sh_offset + off + initial_size + off_size + aug_len + 1, SEEK_SET);

                char aug_data[128];
                int aug_data_len = 0;

                if (aug[0] == 'z')
                {
                    read_leb128(fd, 0, 0);
                    read_leb128(fd, 0, 1);

                    if (version == 1)
                    {
                        char dummy;
                        read(fd, &dummy, 1);
                    }
                    else
                    {
                        read_leb128(fd, 0, 0);
                    }

                    aug_data_len = read_leb128(fd, 0, 0);
                    read(fd, &aug_data[0], aug_data_len);
                }

                if (aug_data_len)
                {
                    char* p;
                    char* q;
                    p = &aug[1];
                    q = &aug_data[0];

                    for (; ; ++p)
                    {
                        if (*p == 'L')
                            q++;
                        else if (*p == 'P')
                            q += 1 + size_of_encoded_value(*q);
                        else if (*p == 'R')
                            ptr_encoding = *q++;
                        else
                            break;
                    }

                    if (ptr_encoding)
                    {
                        encoded_ptr_size = size_of_encoded_value(ptr_encoding);
                    }
                }
            }
            else
            {
                // Read the address of the entry
                uintptr_t addr = get_encoded_value(fd, ptr_encoding);
                if ((ptr_encoding & 0x70) == 0x10)
                {
                    int pos = lseek(fd, 0, SEEK_CUR);
                    addr += shdr.sh_addr + (pos - shdr.sh_offset) - sizeof(uint32_t);
                }

                // Read the size of the entry
                uint32_t size;
                read(fd, (char*) &size, encoded_ptr_size);

                // Get the associated file data, without
                //   touching the current position
                // As it is a PIE executable, address is same
                //   as file offset for low sections
                int pos = lseek(fd, 0, SEEK_CUR);
                lseek(fd, addr, SEEK_SET);
                char data[size];
                read(fd, &data[0], size);
                lseek(fd, pos, SEEK_SET);

                const char* separator = " ";
                if (opt_csv)
                    separator = ", ";

                if (opt_dec)
                    printf("%10ld%s%6d", addr, separator, size);
                else
                    printf("0x%08lX%s%6d", addr, separator, size);

                char name_buf[256] = "";
                if (symbol_name(fd, addr, &name_buf[0], sizeof(name_buf)))
                    printf("%s%s", separator, &name_buf[0]);

                printf("\n");
            }

            off = block_end;
        }
    }

    return 0;
}

void copyright()
{
    printf("Copyright (c) Alexandre Monti 2016, QC\n");
    printf("Contact : monti (at) etud (dot) insa-toulouse (dot) fr\n");
}

void usage(char* progname)
{
    printf("Usage: %s [options] <file>\n", progname);
}

void help(char* progname)
{
    copyright();
    usage(progname);

    printf("Available options :\n");
    printf("  -h, --help   : show this help and exit\n");
    printf("  -c, --csv    : format the output in comma-separated values\n");
    printf("  -d, --decimal: don't use hexadecimal representations in output\n");
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return -1;
    }

    int opt_start = 1;
    int opt_end = opt_start;

    for (; argv[opt_end][0] == '-'; ++opt_end)
    {
        char* opt = &argv[opt_end][1];
        if (!strcmp(opt, "c") || !strcmp(opt, "-csv"))
        {
            opt_csv = 1;
        }
        else if (!strcmp(opt, "d") || !strcmp(opt, "-decimal"))
        {
            opt_dec = 1;
        }
        else if (!strcmp(opt, "h") || !strcmp(opt, "-help"))
        {
            help(argv[0]);
            return 0;
        }
        else
        {
            printf("Error: unknown option '%s'\n", argv[opt_end]);
            return -1;
        }
    }

    if (opt_end >= argc)
    {
        printf("Error: no file specified");
        return -1;
    }

    char* file = argv[opt_end];

    if (opt_end != argc - 1)
        printf("Warning: arguments starting with '%s' will be ignored\n", argv[opt_end+1]);
    
    int fd = open(file, O_RDONLY);
    if (fd < 0)
    {
        printf("Error: unable to open file '%s' for reading\n", file);
        return -1;
    }

    read_dwarf2(fd);

    close(fd);

    return 0;
}
