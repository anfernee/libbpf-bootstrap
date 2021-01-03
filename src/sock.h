
// from uapi/linux/if_packet.h
#define PACKET_HOST 0      /* To us		*/
#define PACKET_BROADCAST 1 /* To all		*/
#define PACKET_MULTICAST 2 /* To group		*/
#define PACKET_OTHERHOST 3 /* To someone else 	*/
#define PACKET_OUTGOING 4  /* Outgoing of any type */
#define PACKET_LOOPBACK 5  /* MC/BRD frame looped back */
#define PACKET_USER 6      /* To user space	*/
#define PACKET_KERNEL 7    /* To kernel space	*/
/* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
#define PACKET_FASTROUTE 6 /* Fastrouted frame	*/

// from uapi/linux/if_ether.h
#define ETH_ALEN 6         /* Octets in one ethernet addr	 */
#define ETH_TLEN 2         /* Octets in ethernet type field */
#define ETH_HLEN 14        /* Total octets in header.	 */
#define ETH_ZLEN 60        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN 1500  /* Max. octets in payload	 */
#define ETH_FRAME_LEN 1514 /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN 4      /* Octets in the FCS		 */

#define ETH_MIN_MTU 68      /* Min IPv4 MTU per RFC791	*/
#define ETH_MAX_MTU 0xFFFFU /* 65535, same as IP_MAX_MTU	*/

// from tools/testing/selftests/bpf/bpf_legacy.h

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */

/*

llvm builtin failing to generate skele:

GEN-SKEL .output/sock.skel.h
libbpf: elf: skipping unrecognized data section(4) .rodata.str1.1
libbpf: failed to find BTF for extern 'load_byte': -2
Error: failed to open BPF object file: No such file or directory
make: *** [Makefile:66: .output/sock.skel.h] Error 255
make: *** Deleting file '.output/sock.skel.h'


unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");
*/