/*	$OpenBSD: hifn7751.c,v 1.120 2002/05/17 00:33:34 deraadt Exp $	*/

/*-
 * Invertex AEON / Hifn 7751 driver
 * Copyright (c) 1999 Invertex Inc. All rights reserved.
 * Copyright (c) 1999 Theo de Raadt
 * Copyright (c) 2000-2001 Network Security Technologies, Inc.
 *			http://www.netsec.net
 * Copyright (c) 2003 Hifn Inc.
 *
 * This driver is based on a previous driver by Invertex, for which they
 * requested:  Please send any comments, feedback, bug-fixes, or feature
 * requests to software@invertex.com.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 *
__FBSDID("$FreeBSD: src/sys/dev/hifn/hifn7751.c,v 1.32 2005/01/19 17:03:35 sam Exp $");
 */

/*
 * Driver for various Hifn encryption processors.
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/uio.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <asm/io.h>

#include <crypto/cryptodev.h>
#include "hifn7751reg.h"
#include "hifn7751var.h"

#define HIFN_DEBUG 

#ifdef HIFN_HEXDUMP
#define hexdump_printf printk
#include "hexdump.c"
#endif

#define KASSERT(c,p)	if (!(c)) { printk p ; } else

#if 1
#define	DPRINTF(a...)	if (debug) { printk("hifn-D: " a); } else
#else
#define	DPRINTF(a...)
#endif

#if 1
#define device_printf(dev, a...) hifn_device_printf(dev, a)
#else
#define device_printf(dev, a...) do { printk("hifn:" a); } while(0)
#endif
#define printf(a...) printk(a)

#define strtoul simple_strtoul
#define DELAY(x)	((x) > 2000 ? mdelay((x)/1000) : udelay(x))

#define bcopy(s,d,l)			memcpy(d,s,l)
#define bzero(p,l)				memset(p,0,l)
#define bcmp(x, y, l)			memcmp(x,y,l)
#define read_random(p,l) get_random_bytes(p,l)

#define htole32(x) cpu_to_le32(x)
#define htole16(x) cpu_to_le16(x)

#define MIN(x,y)	((x) < (y) ? (x) : (y))

#define pci_get_vendor(dev)	((dev)->vendor)
#define pci_get_device(dev)	((dev)->device)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pci_set_consistent_dma_mask(dev, mask) (0)
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
#define pci_dma_sync_single_for_cpu pci_dma_sync_single
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif

static inline int
pci_get_revid(struct pci_dev *dev)
{
	u8 rid = 0;
	pci_read_config_byte(dev, PCI_REVISION_ID, &rid);
	return rid;
}

static	struct hifn_stats hifnstats;

#define	hifn_debug debug
static	int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable debug");

static	int hifn_maxbatch = 1;
module_param(hifn_maxbatch, int, 0644);
MODULE_PARM_DESC(hifn_maxbatch, "max ops to batch w/o interrupt");

static	char hifn_pllconfig[128];
module_param_string(hifn_pllconfig, hifn_pllconfig, 128, 0644);
MODULE_PARM_DESC(hifn_pllconfig, "PLL config, ie., pci66, ext33, ...");

/*
 * Prototypes and count for the pci_device structure
 */
static int hifn_device_printf(struct pci_dev *dev, const char *msg, ...);
static	int  hifn_probe(struct pci_dev *dev, const struct pci_device_id *ent);
static	void hifn_remove(struct pci_dev *dev);

static	void hifn_reset_board(struct hifn_softc *, int);
static	void hifn_reset_puc(struct hifn_softc *);
static	void hifn_puc_wait(struct hifn_softc *);
static	int hifn_enable_crypto(struct hifn_softc *);
static	void hifn_set_retry(struct hifn_softc *sc);
static	void hifn_init_dma(struct hifn_softc *);
static	void hifn_init_pci_registers(struct hifn_softc *);
static	int hifn_sramsize(struct hifn_softc *);
static	int hifn_dramsize(struct hifn_softc *);
static	int hifn_ramtype(struct hifn_softc *);
static	void hifn_sessions(struct hifn_softc *);
static irqreturn_t hifn_intr(int irq, void *arg, struct pt_regs *regs);
static	u_int hifn_write_command(struct hifn_command *, u_int8_t *);
static	u_int32_t hifn_next_signature(u_int32_t a, u_int cnt);
static	int hifn_newsession(void *, u_int32_t *, struct cryptoini *);
static	int hifn_freesession(void *, u_int64_t);
static	int hifn_process(void *, struct cryptop *, int);
static	void hifn_callback(struct hifn_softc *, struct hifn_command *, u_int8_t *);
static	int hifn_crypto(struct hifn_softc *, struct hifn_command *, struct cryptop *, int);
static	int hifn_readramaddr(struct hifn_softc *, int, u_int8_t *);
static	int hifn_writeramaddr(struct hifn_softc *, int, u_int8_t *);
static	int hifn_dmamap_load_src(struct hifn_softc *, struct hifn_command *);
static	int hifn_dmamap_load_dst(struct hifn_softc *, struct hifn_command *);

static	int hifn_init_pkrng(struct hifn_softc *);

static	void hifn_tick(unsigned long arg);
static	void hifn_abort(struct hifn_softc *);
static	void hifn_alloc_slot(struct hifn_softc *, int *, int *, int *, int *);

static	void hifn_write_reg_0(struct hifn_softc *, bus_size_t, u_int32_t);
static	void hifn_write_reg_1(struct hifn_softc *, bus_size_t, u_int32_t);

static	int hifn_read_random(void *arg, u_int32_t *buf, int len);


/* for PK code */
#if defined(CONFIG_OCF_HIFN_PKMMAP)
static struct miscdevice hifnpk_miscdev;
#else
static void hifn_pk_timeout(unsigned long arg);
static void hifn_kintr(struct hifn_softc *sc);
static void hifn_pk_print_status(struct hifn_softc *sc, char *str, u_int32_t stat);
static void hifn_kfeed(struct hifn_softc *sc);
static int hifn_vulcan_kstart(struct hifn_softc *sc);
static int hifn_vulcan_kprocess(void *arg, struct cryptkop *krp, int hint);
#endif



#define HIFN_MAX_CHIPS	8
static int hifn_num_chips = 0;
static struct hifn_softc *hifn_chip_idx[HIFN_MAX_CHIPS];

static __inline u_int32_t
READ_REG_0(struct hifn_softc *sc, bus_size_t reg)
{
	u_int32_t v = readl(sc->sc_bar0 + reg);
	sc->sc_bar0_lastreg = (bus_size_t) -1;
	return (v);
}
#define	WRITE_REG_0(sc, reg, val)	hifn_write_reg_0(sc, reg, val)

static __inline u_int32_t
READ_REG_1(struct hifn_softc *sc, bus_size_t reg)
{
	u_int32_t v = readl(sc->sc_bar1 + reg);
	sc->sc_bar1_lastreg = (bus_size_t) -1;
	return (v);
}
#define	WRITE_REG_1(sc, reg, val)	hifn_write_reg_1(sc, reg, val)

/*
 * map in a given buffer (great on some arches :-)
 */

static int
pci_map_uio(struct hifn_softc *sc, struct hifn_operand *buf, struct uio *uio)
{
	struct iovec *iov = uio->uio_iov;

	DPRINTF("%s()\n", __FUNCTION__);

	buf->mapsize = 0;
	for (buf->nsegs = 0; buf->nsegs < uio->uio_iovcnt; ) {
		buf->segs[buf->nsegs].ds_addr = pci_map_single(sc->sc_dev,
				iov->iov_base, iov->iov_len,
				PCI_DMA_BIDIRECTIONAL);
		buf->segs[buf->nsegs].ds_len = iov->iov_len;
		buf->mapsize += iov->iov_len;
		iov++;
		buf->nsegs++;
	}
	/* identify this buffer by the first segment */
	buf->map = (void *) buf->segs[0].ds_addr;
	return(0);
}

/*
 * map in a given sk_buff
 */

static int
pci_map_skb(struct hifn_softc *sc,struct hifn_operand *buf,struct sk_buff *skb)
{
	int i;

	DPRINTF("%s()\n", __FUNCTION__);

	buf->mapsize = 0;

	buf->segs[0].ds_addr = pci_map_single(sc->sc_dev,
			skb->data, skb_headlen(skb), PCI_DMA_BIDIRECTIONAL);
	buf->segs[0].ds_len = skb_headlen(skb);
	buf->mapsize += buf->segs[0].ds_len;

	buf->nsegs = 1;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ) {
		buf->segs[buf->nsegs].ds_len = skb_shinfo(skb)->frags[i].size;
		buf->segs[buf->nsegs].ds_addr = pci_map_single(sc->sc_dev,
				page_address(skb_shinfo(skb)->frags[i].page) +
					skb_shinfo(skb)->frags[i].page_offset,
				buf->segs[buf->nsegs].ds_len, PCI_DMA_BIDIRECTIONAL);
		buf->mapsize += buf->segs[buf->nsegs].ds_len;
		buf->nsegs++;
	}

	/* identify this buffer by the first segment */
	buf->map = (void *) buf->segs[0].ds_addr;
	return(0);
}

/*
 * map in a given contiguous buffer
 */

static int
pci_map_buf(struct hifn_softc *sc,struct hifn_operand *buf, void *b, int len)
{
	DPRINTF("%s()\n", __FUNCTION__);

	buf->mapsize = 0;
	buf->segs[0].ds_addr = pci_map_single(sc->sc_dev,
			b, len, PCI_DMA_BIDIRECTIONAL);
	buf->segs[0].ds_len = len;
	buf->mapsize += buf->segs[0].ds_len;
	buf->nsegs = 1;

	/* identify this buffer by the first segment */
	buf->map = (void *) buf->segs[0].ds_addr;
	return(0);
}

#if 0 /* not needed at this time */
static void
pci_sync_iov(struct hifn_softc *sc, struct hifn_operand *buf)
{
	int i;

	DPRINTF("%s()\n", __FUNCTION__);
	for (i = 0; i < buf->nsegs; i++)
		pci_dma_sync_single_for_cpu(sc->sc_dev, buf->segs[i].ds_addr,
				buf->segs[i].ds_len, PCI_DMA_BIDIRECTIONAL);
}
#endif

int hifn_device_printf(struct pci_dev *dev, const char *msg, ...)
{
	struct hifn_softc *sc = pci_get_drvdata(dev); 
	va_list args;
	int r;

	printk(KERN_INFO "hifn[%d]: ", sc->sc_num); 

	va_start(args, msg);
	r = vprintk(msg, args);
	va_end(args);

	return r;
}


static void
pci_unmap_buf(struct hifn_softc *sc, struct hifn_operand *buf)
{
	int i;
	DPRINTF("%s()\n", __FUNCTION__);
	for (i = 0; i < buf->nsegs; i++) {
		pci_unmap_single(sc->sc_dev, buf->segs[i].ds_addr,
				buf->segs[i].ds_len, PCI_DMA_BIDIRECTIONAL);
		buf->segs[i].ds_addr = 0;
		buf->segs[i].ds_len = 0;
	}
	buf->nsegs = 0;
	buf->mapsize = 0;
	buf->map = 0;
}

static void
skb_copy_bits_back(struct sk_buff *skb, int offset, caddr_t cp, int len)
{
	int i;
	if (offset < skb_headlen(skb)) {
		memcpy(skb->data + offset, cp, min_t(int, skb_headlen(skb), len));
		len -= skb_headlen(skb);
		cp += skb_headlen(skb);
	}
	offset -= skb_headlen(skb);
	for (i = 0; len > 0 && i < skb_shinfo(skb)->nr_frags; i++) {
		if (offset < skb_shinfo(skb)->frags[i].size) {
			memcpy(page_address(skb_shinfo(skb)->frags[i].page) +
					skb_shinfo(skb)->frags[i].page_offset,
					cp, min_t(int, skb_shinfo(skb)->frags[i].size, len));
			len -= skb_shinfo(skb)->frags[i].size;
			cp += skb_shinfo(skb)->frags[i].size;
		}
		offset -= skb_shinfo(skb)->frags[i].size;
	}
}


static const char*
hifn_partname(struct hifn_softc *sc)
{
	/* XXX sprintf numbers when not decoded */
	switch (pci_get_vendor(sc->sc_dev)) {
	case PCI_VENDOR_HIFN:
		switch (pci_get_device(sc->sc_dev)) {
		case PCI_PRODUCT_HIFN_7751:	return "Hifn 7751";
		case PCI_PRODUCT_HIFN_7951:	return "Hifn 7951";
		case PCI_PRODUCT_HIFN_7955:	return "Hifn 7955";
		case PCI_PRODUCT_HIFN_7956:	return "Hifn 7956";
		}
		return "Hifn unknown-part";
	case PCI_VENDOR_INVERTEX:
		switch (pci_get_device(sc->sc_dev)) {
		case PCI_PRODUCT_INVERTEX_AEON:	return "Invertex AEON";
		}
		return "Invertex unknown-part";
	case PCI_VENDOR_NETSEC:
		switch (pci_get_device(sc->sc_dev)) {
		case PCI_PRODUCT_NETSEC_7751:	return "NetSec 7751";
		}
		return "NetSec unknown-part";
	}
	return "Unknown-vendor unknown-part";
}

static u_int
checkmaxmin(struct pci_dev *dev, const char *what, u_int v, u_int min, u_int max)
{
	if (v > max) {
		device_printf(dev, "Warning, %s %u out of range, "
			"using max %u\n", what, v, max);
		v = max;
	} else if (v < min) {
		device_printf(dev, "Warning, %s %u out of range, "
			"using min %u\n", what, v, min);
		v = min;
	}
	return v;
}

/*
 * Select PLL configuration for 795x parts.  This is complicated in
 * that we cannot determine the optimal parameters without user input.
 * The reference clock is derived from an external clock through a
 * multiplier.  The external clock is either the host bus (i.e. PCI)
 * or an external clock generator.  When using the PCI bus we assume
 * the clock is either 33 or 66 MHz; for an external source we cannot
 * tell the speed.
 *
 * PLL configuration is done with a string: "pci" for PCI bus, or "ext"
 * for an external source, followed by the frequency.  We calculate
 * the appropriate multiplier and PLL register contents accordingly.
 *
 * According Mike Ham of HiFn, almost every board in existence has
 * an external crystal populated at 66Mhz. Using PCI can be a problem
 * on modern motherboards, because PCI33 can have clocks from 0 to 33Mhz,
 * and some have non-PCI-compliant spread-spectrum clocks, which can confuse
 * the pll.
 *
 * On Linux, there is no way to set pllconfig except on the boot
 * command line for static kernels. Even though the string can get adjusted
 * afterwards, the device will not be reconfigured.
 *
 */
static void
hifn_getpllconfig(struct pci_dev *dev, u_int *pll)
{
	const char *pllspec = hifn_pllconfig;
	u_int freq, mul, fl, fh;
	u_int32_t pllconfig;
	char *nxt;

	if (pllspec[0]=='\0')
		pllspec = "ext66";
	fl = 33, fh = 66;
	pllconfig = 0;
	if (strncmp(pllspec, "ext", 3) == 0) {
		pllspec += 3;
		pllconfig |= HIFN_PLL_REF_SEL;
		switch (pci_get_device(dev)) {
		case PCI_PRODUCT_HIFN_7955:
		case PCI_PRODUCT_HIFN_7956:
			fl = 20, fh = 100;
			break;
#ifdef notyet
		case PCI_PRODUCT_HIFN_7954:
			fl = 20, fh = 66;
			break;
#endif
		}
	} else if (strncmp(pllspec, "pci", 3) == 0)
		pllspec += 3;
	freq = strtoul(pllspec, &nxt, 10);
	if (nxt == pllspec)
		freq = 66;
	else
		freq = checkmaxmin(dev, "frequency", freq, fl, fh);
	/*
	 * Calculate multiplier.  We target a Fck of 266 MHz,
	 * allowing only even values, possibly rounded down.
	 * Multipliers > 8 must set the charge pump current.
	 */
	mul = checkmaxmin(dev, "PLL divisor", (266 / freq) &~ 1, 2, 12);
	pllconfig |= (mul / 2 - 1) << HIFN_PLL_ND_SHIFT;
	if (mul > 8)
		pllconfig |= HIFN_PLL_IS;
	*pll = pllconfig;
}

struct hifn_fs_entry {
	struct attribute attr;
	/* other stuff */
};



static ssize_t
cryptoid_show(struct device *dev,
	      struct device_attribute *attr,
	      char *buf)						
{								
	struct hifn_softc *sc;					

	sc = pci_get_drvdata(to_pci_dev (dev));
	return sprintf (buf, "%d\n", sc->sc_cid);
}

struct device_attribute hifn_dev_cryptoid = __ATTR_RO(cryptoid);

/*
 * Attach an interface that successfully probed.
 */
static int
hifn_probe(struct pci_dev *dev, const struct pci_device_id *ent)
{
	struct hifn_softc *sc;
	char rbase;
	u_int16_t ena, rev;
	int rseg, rc;
	unsigned long mem_start, mem_len;

	DPRINTF("%s()\n", __FUNCTION__);

	if (pci_enable_device(dev) < 0)
		return(-ENODEV);

	if (pci_set_mwi(dev))
		return(-ENODEV);

	if (!dev->irq) {
		printk("hifn: found device with no IRQ assigned. check BIOS settings!");
		pci_disable_device(dev);
		return(-ENODEV);
	}

	sc = (struct hifn_softc *) kmalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return(-ENOMEM);
	memset(sc, 0, sizeof(*sc));
	sc->sc_dev = dev;
	sc->sc_irq = -1;
	sc->sc_cid = -1;
	sc->sc_num = hifn_num_chips++;

	if (sc->sc_num < HIFN_MAX_CHIPS)
		hifn_chip_idx[sc->sc_num] = sc;

	pci_set_drvdata(sc->sc_dev, sc);

	spin_lock_init(&sc->sc_mtx);

	/* XXX handle power management */

	/*
	 * The 7951 and 795x have a random number generator and
	 * public key support; note this.
	 */
	if (pci_get_vendor(dev) == PCI_VENDOR_HIFN &&
	    (pci_get_device(dev) == PCI_PRODUCT_HIFN_7951 ||
	     pci_get_device(dev) == PCI_PRODUCT_HIFN_7955 ||
	     pci_get_device(dev) == PCI_PRODUCT_HIFN_7956))
		sc->sc_flags = HIFN_HAS_RNG | HIFN_HAS_PUBLIC;
	/*
	 * The 7811 has a random number generator and
	 * we also note it's identity 'cuz of some quirks.
	 */
	if (pci_get_vendor(dev) == PCI_VENDOR_HIFN &&
	    pci_get_device(dev) == PCI_PRODUCT_HIFN_7811)
		sc->sc_flags |= HIFN_IS_7811 | HIFN_HAS_RNG;

	/*
	 * The 795x parts support AES.
	 */
	if (pci_get_vendor(dev) == PCI_VENDOR_HIFN &&
	    (pci_get_device(dev) == PCI_PRODUCT_HIFN_7955 ||
	     pci_get_device(dev) == PCI_PRODUCT_HIFN_7956)) {
		sc->sc_flags |= HIFN_IS_7956 | HIFN_HAS_AES;
		/*
		 * Select PLL configuration.  This depends on the
		 * bus and board design and must be manually configured
		 * if the default setting is unacceptable.
		 */
		hifn_getpllconfig(dev, &sc->sc_pllconfig);
	}

	/*
	 * Setup PCI resources.
	 * The READ_REG_0, WRITE_REG_0, READ_REG_1,
	 * and WRITE_REG_1 macros throughout the driver are used
	 * because some parts can not handle back-to-back operations.
	 */
	mem_start = pci_resource_start(sc->sc_dev, 0);
	mem_len   = pci_resource_len(sc->sc_dev, 0);
	sc->sc_bar0phy = mem_start;
	sc->sc_bar0 = (ocf_iomem_t) ioremap(mem_start, mem_len);
	if (!sc->sc_bar0) {
		device_printf(dev, "cannot map bar%d register space\n", 0);
		goto fail;
	}
	sc->sc_bar0_lastreg = (bus_size_t) -1;

	mem_start = pci_resource_start(sc->sc_dev, 1);
	mem_len   = pci_resource_len(sc->sc_dev, 1);
	sc->sc_bar1phy = mem_start;
	sc->sc_bar1 = (ocf_iomem_t) ioremap(mem_start, mem_len);
	if (!sc->sc_bar1) {
		device_printf(dev, "cannot map bar%d register space\n", 1);
		goto fail;
	}
	sc->sc_bar1_lastreg = (bus_size_t) -1;

	/* fix up the bus size */
	if (pci_set_dma_mask(dev, DMA_32BIT_MASK)) {
		device_printf(dev, "No usable DMA configuration, aborting.\n");
		goto fail;
	}
	if (pci_set_consistent_dma_mask(dev, DMA_32BIT_MASK)) {
		device_printf(dev,
				"No usable consistent DMA configuration, aborting.\n");
		goto fail;
	}

	hifn_set_retry(sc);

	/*
	 * Setup the area where the Hifn DMA's descriptors
	 * and associated data structures.
	 */
	sc->sc_dma = (struct hifn_dma *) pci_alloc_consistent(dev,
			sizeof(*sc->sc_dma),
			&sc->sc_dma_physaddr);
	if (!sc->sc_dma) {
		device_printf(dev, "cannot alloc sc_dma\n");
		goto fail;
	}
	bzero(sc->sc_dma, sizeof(*sc->sc_dma));

	/*
	 * Reset the board and do the ``secret handshake''
	 * to enable the crypto support.  Then complete the
	 * initialization procedure by setting up the interrupt
	 * and hooking in to the system crypto support so we'll
	 * get used for system services like the crypto device,
	 * IPsec, RNG device, etc.
	 */
	hifn_reset_board(sc, 0);

	if (hifn_enable_crypto(sc) != 0) {
		device_printf(dev, "crypto enabling failed\n");
		goto fail;
	}
	hifn_reset_puc(sc);

	hifn_init_dma(sc);
	hifn_init_pci_registers(sc);

	pci_set_master(sc->sc_dev);

	/* XXX can't dynamically determine ram type for 795x; force dram */
	if (sc->sc_flags & HIFN_IS_7956)
		sc->sc_drammodel = 1;
	else if (hifn_ramtype(sc))
		goto fail;

	if (sc->sc_drammodel == 0)
		hifn_sramsize(sc);
	else
		hifn_dramsize(sc);

	/*
	 * Workaround for NetSec 7751 rev A: half ram size because two
	 * of the address lines were left floating
	 */
	if (pci_get_vendor(dev) == PCI_VENDOR_NETSEC &&
	    pci_get_device(dev) == PCI_PRODUCT_NETSEC_7751 &&
	    pci_get_revid(dev) == 0x61)	/*XXX???*/
		sc->sc_ramsize >>= 1;

	/*
	 * Arrange the interrupt line.
	 */
	rc = request_irq(dev->irq, hifn_intr, SA_SHIRQ, "hifn", sc);
	if (rc) {
		device_printf(dev, "could not map interrupt: %d\n", rc);
		goto fail;
	}
	sc->sc_irq = dev->irq;

	hifn_sessions(sc);

	/*
	 * NB: Keep only the low 16 bits; this masks the chip id
	 *     from the 7951.
	 */
	rev = READ_REG_1(sc, HIFN_1_REVID) & 0xffff;

	rseg = sc->sc_ramsize / 1024;
	rbase = 'K';
	if (sc->sc_ramsize >= (1024 * 1024)) {
		rbase = 'M';
		rseg /= 1024;
	}
	device_printf(sc->sc_dev, "%s, rev %u, %d%cB %cram",
		hifn_partname(sc), rev,
		rseg, rbase, sc->sc_drammodel ? 'd' : 's');
	if (sc->sc_flags & HIFN_IS_7956)
		printf(", pll=0x%x<%s clk, %ux mult>",
			sc->sc_pllconfig,
			sc->sc_pllconfig & HIFN_PLL_REF_SEL ? "ext" : "pci",
			2 + 2*((sc->sc_pllconfig & HIFN_PLL_ND) >> 11));
	printf("\n");

	sc->sc_cid = crypto_get_driverid(0, "hifn-vulcan");
	if (sc->sc_cid < 0) {
		device_printf(dev, "could not get crypto driver id\n");
		goto fail;
	}

	/* make a sysfs entry to let the world know what entry we got */
	sysfs_create_file(&sc->sc_dev->dev.kobj, &hifn_dev_cryptoid.attr);


	WRITE_REG_0(sc, HIFN_0_PUCNFG,
	    READ_REG_0(sc, HIFN_0_PUCNFG) | HIFN_PUCNFG_CHIPID);
	ena = READ_REG_0(sc, HIFN_0_PUSTAT) & HIFN_PUSTAT_CHIPENA;

	switch (ena) {
	case HIFN_PUSTAT_ENA_2:
		crypto_register(sc->sc_cid, CRYPTO_3DES_CBC, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		crypto_register(sc->sc_cid, CRYPTO_ARC4, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		if (sc->sc_flags & HIFN_HAS_AES)
			crypto_register(sc->sc_cid, CRYPTO_AES_CBC,  0, 0,
				hifn_newsession, hifn_freesession,
				hifn_process, sc);
		/*FALLTHROUGH*/
	case HIFN_PUSTAT_ENA_1:
		crypto_register(sc->sc_cid, CRYPTO_MD5, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		crypto_register(sc->sc_cid, CRYPTO_SHA1, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		crypto_register(sc->sc_cid, CRYPTO_MD5_HMAC, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		crypto_register(sc->sc_cid, CRYPTO_SHA1_HMAC, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		crypto_register(sc->sc_cid, CRYPTO_DES_CBC, 0, 0,
		    hifn_newsession, hifn_freesession, hifn_process, sc);
		break;
	}

	if (sc->sc_flags & (HIFN_HAS_PUBLIC | HIFN_HAS_RNG))
		hifn_init_pkrng(sc);

	init_timer(&sc->sc_tickto);
	sc->sc_tickto.function = hifn_tick;
	sc->sc_tickto.data = (unsigned long) sc->sc_num;
	mod_timer(&sc->sc_tickto, jiffies + HZ);

	return (0);

fail:
    if (sc->sc_cid >= 0)
        crypto_unregister_all(sc->sc_cid);
    if (sc->sc_irq != -1)
        free_irq(sc->sc_irq, sc);
    if (sc->sc_dma) {
		/* Turn off DMA polling */
		WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_MSTRESET |
			HIFN_DMACNFG_DMARESET | HIFN_DMACNFG_MODE);

        pci_free_consistent(sc->sc_dev,
				sizeof(*sc->sc_dma),
                sc->sc_dma, sc->sc_dma_physaddr);
	}
    kfree(sc);
	return (-ENXIO);
}

/*
 * Detach an interface that successfully probed.
 */
static void
hifn_remove(struct pci_dev *dev)
{
	struct hifn_softc *sc = pci_get_drvdata(dev);
	unsigned long l_flags;

	DPRINTF("%s()\n", __FUNCTION__);

	KASSERT(sc != NULL, ("hifn_detach: null software carrier!"));

	/* disable interrupts */
	HIFN_LOCK(sc);
	WRITE_REG_1(sc, HIFN_1_DMA_IER, 0);
	HIFN_UNLOCK(sc);

	/*XXX other resources */
	del_timer_sync(&sc->sc_tickto);

	/* Turn off DMA polling */
	WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_MSTRESET |
	    HIFN_DMACNFG_DMARESET | HIFN_DMACNFG_MODE);

	crypto_unregister_all(sc->sc_cid);

	free_irq(sc->sc_irq, sc);

	pci_free_consistent(sc->sc_dev, sizeof(*sc->sc_dma),
                sc->sc_dma, sc->sc_dma_physaddr);
}


static int
hifn_read_random(void *arg, u_int32_t *buf, int len)
{
	struct hifn_softc *sc = (struct hifn_softc *) arg;
	u_int32_t sts;
	int i, rc = 0;

	if (len <= 0)
		return rc;

	if (sc->sc_flags & HIFN_IS_7811) {
		for (i = 0; i < 5; i++) {
			sts = READ_REG_1(sc, HIFN_1_7811_RNGSTS);
			if (sts & HIFN_7811_RNGSTS_UFL) {
				device_printf(sc->sc_dev,
					      "RNG underflow: disabling\n");
				/* DAVIDM perhaps return -1 */
				break;
			}
			if ((sts & HIFN_7811_RNGSTS_RDY) == 0)
				break;

			/*
			 * There are at least two words in the RNG FIFO
			 * at this point.
			 */
			if (rc < len)
				buf[rc++] = READ_REG_1(sc, HIFN_1_7811_RNGDAT);
			if (rc < len)
				buf[rc++] = READ_REG_1(sc, HIFN_1_7811_RNGDAT);
			/* NB: discard first data read */
			if (sc->sc_rngfirst) {
				sc->sc_rngfirst = 0;
				rc = 0;
			}
		}
	} else {
		/* must be a 7855, which has no real timing issues, return
		 * as much as requested.
		 */
		while(len-- > 0) {
			buf[rc++] = READ_REG_1(sc, HIFN_1_RNG_DATA);
		}
	}

	return(rc);
}

static void
hifn_puc_wait(struct hifn_softc *sc)
{
	int i;

	DPRINTF("%s()\n", __FUNCTION__);

	for (i = 5000; i > 0; i--) {
		DELAY(1);
		if (!(READ_REG_0(sc, HIFN_0_PUCTRL) & HIFN_PUCTRL_RESET))
			break;
	}
	if (!i)
		device_printf(sc->sc_dev, "proc unit did not reset(0x%x)\n",
				READ_REG_0(sc, HIFN_0_PUCTRL));
}

/*
 * Reset the processing unit.
 */
static void
hifn_reset_puc(struct hifn_softc *sc)
{
	/* Reset processing unit */
	WRITE_REG_0(sc, HIFN_0_PUCTRL, HIFN_PUCTRL_DMAENA);
	hifn_puc_wait(sc);
}

/*
 * Set the Retry and TRDY registers; note that we set them to
 * zero because the 7811 locks up when forced to retry (section
 * 3.6 of "Specification Update SU-0014-04".  Not clear if we
 * should do this for all Hifn parts, but it doesn't seem to hurt.
 */
static void
hifn_set_retry(struct hifn_softc *sc)
{
	DPRINTF("%s()\n", __FUNCTION__);
	/* NB: RETRY only responds to 8-bit reads/writes */
	pci_write_config_byte(sc->sc_dev, HIFN_RETRY_TIMEOUT, 0);
	pci_write_config_dword(sc->sc_dev, HIFN_TRDY_TIMEOUT, 0);
}

/*
 * Resets the board.  Values in the regesters are left as is
 * from the reset (i.e. initial values are assigned elsewhere).
 */
static void
hifn_reset_board(struct hifn_softc *sc, int full)
{
	u_int32_t reg;

	DPRINTF("%s()\n", __FUNCTION__);
	/*
	 * Set polling in the DMA configuration register to zero.  0x7 avoids
	 * resetting the board and zeros out the other fields.
	 */
	WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_MSTRESET |
	    HIFN_DMACNFG_DMARESET | HIFN_DMACNFG_MODE);

	/*
	 * Now that polling has been disabled, we have to wait 1 ms
	 * before resetting the board.
	 */
	DELAY(1000);

	/* Reset the DMA unit */
	if (full) {
		WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_MODE);
		DELAY(1000);
	} else {
		WRITE_REG_1(sc, HIFN_1_DMA_CNFG,
		    HIFN_DMACNFG_MODE | HIFN_DMACNFG_MSTRESET);
		hifn_reset_puc(sc);
	}

	KASSERT(sc->sc_dma != NULL, ("hifn_reset_board: null DMA tag!"));
	bzero(sc->sc_dma, sizeof(*sc->sc_dma));

	/* Bring dma unit out of reset */
	WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_MSTRESET |
	    HIFN_DMACNFG_DMARESET | HIFN_DMACNFG_MODE);

	hifn_puc_wait(sc);
	hifn_set_retry(sc);

	if (sc->sc_flags & HIFN_IS_7811) {
		for (reg = 0; reg < 1000; reg++) {
			if (READ_REG_1(sc, HIFN_1_7811_MIPSRST) &
			    HIFN_MIPSRST_CRAMINIT)
				break;
			DELAY(1000);
		}
		if (reg == 1000)
			device_printf(sc->sc_dev, ": cram init timeout\n");
	}
}

static u_int32_t
hifn_next_signature(u_int32_t a, u_int cnt)
{
	int i;
	u_int32_t v;

	for (i = 0; i < cnt; i++) {

		/* get the parity */
		v = a & 0x80080125;
		v ^= v >> 16;
		v ^= v >> 8;
		v ^= v >> 4;
		v ^= v >> 2;
		v ^= v >> 1;

		a = (v & 1) ^ (a << 1);
	}

	return a;
}


/*
 * Checks to see if crypto is already enabled.  If crypto isn't enable,
 * "hifn_enable_crypto" is called to enable it.  The check is important,
 * as enabling crypto twice will lock the board.
 */
static int 
hifn_enable_crypto(struct hifn_softc *sc)
{
	u_int32_t dmacfg, ramcfg, encl, addr, i;
	char offtbl[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00 };

	DPRINTF("%s()\n", __FUNCTION__);

	ramcfg = READ_REG_0(sc, HIFN_0_PUCNFG);
	dmacfg = READ_REG_1(sc, HIFN_1_DMA_CNFG);

	/*
	 * The RAM config register's encrypt level bit needs to be set before
	 * every read performed on the encryption level register.
	 */
	WRITE_REG_0(sc, HIFN_0_PUCNFG, ramcfg | HIFN_PUCNFG_CHIPID);

	encl = READ_REG_0(sc, HIFN_0_PUSTAT) & HIFN_PUSTAT_CHIPENA;

	/*
	 * Make sure we don't re-unlock.  Two unlocks kills chip until the
	 * next reboot.
	 */
	if (encl == HIFN_PUSTAT_ENA_1 || encl == HIFN_PUSTAT_ENA_2) {
#ifdef HIFN_DEBUG
		if (hifn_debug)
			device_printf(sc->sc_dev,
			    "Strong crypto already enabled!\n");
#endif
		goto report;
	}

	if (encl != 0 && encl != HIFN_PUSTAT_ENA_0) {
#ifdef HIFN_DEBUG
		if (hifn_debug)
			device_printf(sc->sc_dev,
			      "Unknown encryption level 0x%x\n", encl);
#endif
		return 1;
	}

	WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_UNLOCK |
	    HIFN_DMACNFG_MSTRESET | HIFN_DMACNFG_DMARESET | HIFN_DMACNFG_MODE);
	DELAY(1000);
	addr = READ_REG_1(sc, HIFN_UNLOCK_SECRET1);
	DELAY(1000);
	WRITE_REG_1(sc, HIFN_UNLOCK_SECRET2, 0);
	DELAY(1000);

	for (i = 0; i <= 12; i++) {
		addr = hifn_next_signature(addr, offtbl[i] + 0x101);
		WRITE_REG_1(sc, HIFN_UNLOCK_SECRET2, addr);

		DELAY(1000);
	}

	WRITE_REG_0(sc, HIFN_0_PUCNFG, ramcfg | HIFN_PUCNFG_CHIPID);
	encl = READ_REG_0(sc, HIFN_0_PUSTAT) & HIFN_PUSTAT_CHIPENA;

#ifdef HIFN_DEBUG
	if (hifn_debug) {
		if (encl != HIFN_PUSTAT_ENA_1 && encl != HIFN_PUSTAT_ENA_2)
			device_printf(sc->sc_dev, "Engine is permanently "
				"locked until next system reset!\n");
		else
			device_printf(sc->sc_dev, "Engine enabled "
				"successfully!\n");
	}
#endif

report:
	WRITE_REG_0(sc, HIFN_0_PUCNFG, ramcfg);
	WRITE_REG_1(sc, HIFN_1_DMA_CNFG, dmacfg);

	switch (encl) {
	case HIFN_PUSTAT_ENA_1:
	case HIFN_PUSTAT_ENA_2:
		break;
	case HIFN_PUSTAT_ENA_0:
	default:
		device_printf(sc->sc_dev, "engine disabled\n");
		break;
	}

	return 0;
}

/*
 * Give initial values to the registers listed in the "Register Space"
 * section of the HIFN Software Development reference manual.
 */
static void 
hifn_init_pci_registers(struct hifn_softc *sc)
{
	DPRINTF("%s()\n", __FUNCTION__);

	/* write fixed values needed by the Initialization registers */
	WRITE_REG_0(sc, HIFN_0_PUCTRL, HIFN_PUCTRL_DMAENA);
	WRITE_REG_0(sc, HIFN_0_FIFOCNFG, HIFN_FIFOCNFG_THRESHOLD);
	WRITE_REG_0(sc, HIFN_0_PUIER, HIFN_PUIER_DSTOVER);

	/* write all 4 ring address registers */
	WRITE_REG_1(sc, HIFN_1_DMA_CRAR, sc->sc_dma_physaddr +
	    offsetof(struct hifn_dma, cmdr[0]));
	WRITE_REG_1(sc, HIFN_1_DMA_SRAR, sc->sc_dma_physaddr +
	    offsetof(struct hifn_dma, srcr[0]));
	WRITE_REG_1(sc, HIFN_1_DMA_DRAR, sc->sc_dma_physaddr +
	    offsetof(struct hifn_dma, dstr[0]));
	WRITE_REG_1(sc, HIFN_1_DMA_RRAR, sc->sc_dma_physaddr +
	    offsetof(struct hifn_dma, resr[0]));

	DELAY(2000);

	/* write status register */
	WRITE_REG_1(sc, HIFN_1_DMA_CSR,
	    HIFN_DMACSR_D_CTRL_DIS | HIFN_DMACSR_R_CTRL_DIS |
	    HIFN_DMACSR_S_CTRL_DIS | HIFN_DMACSR_C_CTRL_DIS |
	    HIFN_DMACSR_D_ABORT | HIFN_DMACSR_D_DONE | HIFN_DMACSR_D_LAST |
	    HIFN_DMACSR_D_WAIT | HIFN_DMACSR_D_OVER |
	    HIFN_DMACSR_R_ABORT | HIFN_DMACSR_R_DONE | HIFN_DMACSR_R_LAST |
	    HIFN_DMACSR_R_WAIT | HIFN_DMACSR_R_OVER |
	    HIFN_DMACSR_S_ABORT | HIFN_DMACSR_S_DONE | HIFN_DMACSR_S_LAST |
	    HIFN_DMACSR_S_WAIT |
	    HIFN_DMACSR_C_ABORT | HIFN_DMACSR_C_DONE | HIFN_DMACSR_C_LAST |
	    HIFN_DMACSR_C_WAIT |
	    HIFN_DMACSR_ENGINE |
	    ((sc->sc_flags & HIFN_HAS_PUBLIC) ?
		HIFN_DMACSR_PUBDONE : 0) |
	    ((sc->sc_flags & HIFN_IS_7811) ?
		HIFN_DMACSR_ILLW | HIFN_DMACSR_ILLR : 0));

	sc->sc_d_busy = sc->sc_r_busy = sc->sc_s_busy = sc->sc_c_busy = 0;
	sc->sc_dmaier |= HIFN_DMAIER_R_DONE | HIFN_DMAIER_C_ABORT |
	    HIFN_DMAIER_D_OVER | HIFN_DMAIER_R_OVER |
	    HIFN_DMAIER_S_ABORT | HIFN_DMAIER_D_ABORT | HIFN_DMAIER_R_ABORT |
	    ((sc->sc_flags & HIFN_IS_7811) ?
		HIFN_DMAIER_ILLW | HIFN_DMAIER_ILLR : 0);
	sc->sc_dmaier &= ~HIFN_DMAIER_C_WAIT;
	WRITE_REG_1(sc, HIFN_1_DMA_IER, sc->sc_dmaier);


	if (sc->sc_flags & HIFN_IS_7956) {
		u_int32_t pll;

		WRITE_REG_0(sc, HIFN_0_PUCNFG, HIFN_PUCNFG_COMPSING |
		    HIFN_PUCNFG_TCALLPHASES |
		    HIFN_PUCNFG_TCDRVTOTEM | HIFN_PUCNFG_BUS32);

		/* turn off the clocks and insure bypass is set */
		pll = READ_REG_1(sc, HIFN_1_PLL);
		pll = (pll &~ (HIFN_PLL_PK_CLK_SEL | HIFN_PLL_PE_CLK_SEL))
		    | HIFN_PLL_BP;
		WRITE_REG_1(sc, HIFN_1_PLL, pll);
		DELAY(10*1000);		/* 10ms */
		/* change configuration */
		pll = (pll &~ HIFN_PLL_CONFIG) | sc->sc_pllconfig;
		WRITE_REG_1(sc, HIFN_1_PLL, pll);
		DELAY(10*1000);		/* 10ms */
		/* disable bypass */
		pll &= ~HIFN_PLL_BP;
		WRITE_REG_1(sc, HIFN_1_PLL, pll);
		/* enable clocks with new configuration */
		pll |= HIFN_PLL_PK_CLK_SEL | HIFN_PLL_PE_CLK_SEL;
		WRITE_REG_1(sc, HIFN_1_PLL, pll);
	} else {
		WRITE_REG_0(sc, HIFN_0_PUCNFG, HIFN_PUCNFG_COMPSING |
		    HIFN_PUCNFG_DRFR_128 | HIFN_PUCNFG_TCALLPHASES |
		    HIFN_PUCNFG_TCDRVTOTEM | HIFN_PUCNFG_BUS32 |
		    (sc->sc_drammodel ? HIFN_PUCNFG_DRAM : HIFN_PUCNFG_SRAM));
	}

	WRITE_REG_0(sc, HIFN_0_PUISR, HIFN_PUISR_DSTOVER);
	WRITE_REG_1(sc, HIFN_1_DMA_CNFG, HIFN_DMACNFG_MSTRESET |
	    HIFN_DMACNFG_DMARESET | HIFN_DMACNFG_MODE | HIFN_DMACNFG_LAST |
	    ((HIFN_POLL_FREQUENCY << 16 ) & HIFN_DMACNFG_POLLFREQ) |
	    ((HIFN_POLL_SCALAR << 8) & HIFN_DMACNFG_POLLINVAL));
}

/*
 * The maximum number of sessions supported by the card
 * is dependent on the amount of context ram, which
 * encryption algorithms are enabled, and how compression
 * is configured.  This should be configured before this
 * routine is called.
 */
static void
hifn_sessions(struct hifn_softc *sc)
{
	u_int32_t pucnfg;
	int ctxsize;

	DPRINTF("%s()\n", __FUNCTION__);

	pucnfg = READ_REG_0(sc, HIFN_0_PUCNFG);

	if (pucnfg & HIFN_PUCNFG_COMPSING) {
		if (pucnfg & HIFN_PUCNFG_ENCCNFG)
			ctxsize = 128;
		else
			ctxsize = 512;
		/*
		 * 7955/7956 has internal context memory of 32K
		 */
		if (sc->sc_flags & HIFN_IS_7956)
			sc->sc_maxses = 32768 / ctxsize;
		else
			sc->sc_maxses = 1 +
			    ((sc->sc_ramsize - 32768) / ctxsize);
	} else
		sc->sc_maxses = sc->sc_ramsize / 16384;

	if (sc->sc_maxses > 2048)
		sc->sc_maxses = 2048;
}

/*
 * Determine ram type (sram or dram).  Board should be just out of a reset
 * state when this is called.
 */
static int
hifn_ramtype(struct hifn_softc *sc)
{
	u_int8_t data[8], dataexpect[8];
	int i;

	for (i = 0; i < sizeof(data); i++)
		data[i] = dataexpect[i] = 0x55;
	if (hifn_writeramaddr(sc, 0, data))
		return (-1);
	if (hifn_readramaddr(sc, 0, data))
		return (-1);
	if (bcmp(data, dataexpect, sizeof(data)) != 0) {
		sc->sc_drammodel = 1;
		return (0);
	}

	for (i = 0; i < sizeof(data); i++)
		data[i] = dataexpect[i] = 0xaa;
	if (hifn_writeramaddr(sc, 0, data))
		return (-1);
	if (hifn_readramaddr(sc, 0, data))
		return (-1);
	if (bcmp(data, dataexpect, sizeof(data)) != 0) {
		sc->sc_drammodel = 1;
		return (0);
	}

	return (0);
}

#define	HIFN_SRAM_MAX		(32 << 20)
#define	HIFN_SRAM_STEP_SIZE	16384
#define	HIFN_SRAM_GRANULARITY	(HIFN_SRAM_MAX / HIFN_SRAM_STEP_SIZE)

static int
hifn_sramsize(struct hifn_softc *sc)
{
	u_int32_t a;
	u_int8_t data[8];
	u_int8_t dataexpect[sizeof(data)];
	int32_t i;

	for (i = 0; i < sizeof(data); i++)
		data[i] = dataexpect[i] = i ^ 0x5a;

	for (i = HIFN_SRAM_GRANULARITY - 1; i >= 0; i--) {
		a = i * HIFN_SRAM_STEP_SIZE;
		bcopy(&i, data, sizeof(i));
		hifn_writeramaddr(sc, a, data);
	}

	for (i = 0; i < HIFN_SRAM_GRANULARITY; i++) {
		a = i * HIFN_SRAM_STEP_SIZE;
		bcopy(&i, dataexpect, sizeof(i));
		if (hifn_readramaddr(sc, a, data) < 0)
			return (0);
		if (bcmp(data, dataexpect, sizeof(data)) != 0)
			return (0);
		sc->sc_ramsize = a + HIFN_SRAM_STEP_SIZE;
	}

	return (0);
}

/*
 * XXX For dram boards, one should really try all of the
 * HIFN_PUCNFG_DSZ_*'s.  This just assumes that PUCNFG
 * is already set up correctly.
 */
static int
hifn_dramsize(struct hifn_softc *sc)
{
	u_int32_t cnfg;

	if (sc->sc_flags & HIFN_IS_7956) {
		/*
		 * 7955/7956 have a fixed internal ram of only 32K.
		 */
		sc->sc_ramsize = 32768;
	} else {
		cnfg = READ_REG_0(sc, HIFN_0_PUCNFG) &
		    HIFN_PUCNFG_DRAMMASK;
		sc->sc_ramsize = 1 << ((cnfg >> 13) + 18);
	}
	return (0);
}

static void
hifn_alloc_slot(struct hifn_softc *sc, int *cmdp, int *srcp, int *dstp, int *resp)
{
	struct hifn_dma *dma = sc->sc_dma;

	DPRINTF("%s()\n", __FUNCTION__);

	if (dma->cmdi == HIFN_D_CMD_RSIZE) {
		dma->cmdi = 0;
		dma->cmdr[HIFN_D_CMD_RSIZE].l = htole32(HIFN_D_JUMP|HIFN_D_MASKDONEIRQ);
		wmb();
		dma->cmdr[HIFN_D_CMD_RSIZE].l |= htole32(HIFN_D_VALID);
		HIFN_CMDR_SYNC(sc, HIFN_D_CMD_RSIZE,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	}
	*cmdp = dma->cmdi++;
	dma->cmdk = dma->cmdi;

	if (dma->srci == HIFN_D_SRC_RSIZE) {
		dma->srci = 0;
		dma->srcr[HIFN_D_SRC_RSIZE].l = htole32(HIFN_D_JUMP|HIFN_D_MASKDONEIRQ);
		wmb();
		dma->srcr[HIFN_D_SRC_RSIZE].l |= htole32(HIFN_D_VALID);
		HIFN_SRCR_SYNC(sc, HIFN_D_SRC_RSIZE,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	}
	*srcp = dma->srci++;
	dma->srck = dma->srci;

	if (dma->dsti == HIFN_D_DST_RSIZE) {
		dma->dsti = 0;
		dma->dstr[HIFN_D_DST_RSIZE].l = htole32(HIFN_D_JUMP|HIFN_D_MASKDONEIRQ);
		wmb();
		dma->dstr[HIFN_D_DST_RSIZE].l |= htole32(HIFN_D_VALID);
		HIFN_DSTR_SYNC(sc, HIFN_D_DST_RSIZE,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	}
	*dstp = dma->dsti++;
	dma->dstk = dma->dsti;

	if (dma->resi == HIFN_D_RES_RSIZE) {
		dma->resi = 0;
		dma->resr[HIFN_D_RES_RSIZE].l = htole32(HIFN_D_JUMP|HIFN_D_MASKDONEIRQ);
		wmb();
		dma->resr[HIFN_D_RES_RSIZE].l |= htole32(HIFN_D_VALID);
		HIFN_RESR_SYNC(sc, HIFN_D_RES_RSIZE,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	}
	*resp = dma->resi++;
	dma->resk = dma->resi;
}

static int
hifn_writeramaddr(struct hifn_softc *sc, int addr, u_int8_t *data)
{
	struct hifn_dma *dma = sc->sc_dma;
	hifn_base_command_t wc;
	const u_int32_t masks = HIFN_D_VALID | HIFN_D_LAST | HIFN_D_MASKDONEIRQ;
	int r, cmdi, resi, srci, dsti;

	DPRINTF("%s()\n", __FUNCTION__);

	wc.masks = htole16(3 << 13);
	wc.session_num = htole16(addr >> 14);
	wc.total_source_count = htole16(8);
	wc.total_dest_count = htole16(addr & 0x3fff);

	hifn_alloc_slot(sc, &cmdi, &srci, &dsti, &resi);

	WRITE_REG_1(sc, HIFN_1_DMA_CSR,
	    HIFN_DMACSR_C_CTRL_ENA | HIFN_DMACSR_S_CTRL_ENA |
	    HIFN_DMACSR_D_CTRL_ENA | HIFN_DMACSR_R_CTRL_ENA);

	/* build write command */
	bzero(dma->command_bufs[cmdi], HIFN_MAX_COMMAND);
	*(hifn_base_command_t *)dma->command_bufs[cmdi] = wc;
	bcopy(data, &dma->test_src, sizeof(dma->test_src));

	dma->srcr[srci].p = htole32(sc->sc_dma_physaddr
	    + offsetof(struct hifn_dma, test_src));
	dma->dstr[dsti].p = htole32(sc->sc_dma_physaddr
	    + offsetof(struct hifn_dma, test_dst));

	dma->cmdr[cmdi].l = htole32(16 | masks);
	dma->srcr[srci].l = htole32(8 | masks);
	dma->dstr[dsti].l = htole32(4 | masks);
	dma->resr[resi].l = htole32(4 | masks);

	for (r = 10000; r >= 0; r--) {
		DELAY(10);
		if ((dma->resr[resi].l & htole32(HIFN_D_VALID)) == 0)
			break;
	}
	if (r == 0) {
		device_printf(sc->sc_dev, "writeramaddr -- "
		    "result[%d](addr %d) still valid\n", resi, addr);
		r = -1;
		return (-1);
	} else
		r = 0;

	WRITE_REG_1(sc, HIFN_1_DMA_CSR,
	    HIFN_DMACSR_C_CTRL_DIS | HIFN_DMACSR_S_CTRL_DIS |
	    HIFN_DMACSR_D_CTRL_DIS | HIFN_DMACSR_R_CTRL_DIS);

	return (r);
}

static int
hifn_readramaddr(struct hifn_softc *sc, int addr, u_int8_t *data)
{
	struct hifn_dma *dma = sc->sc_dma;
	hifn_base_command_t rc;
	const u_int32_t masks = HIFN_D_VALID | HIFN_D_LAST | HIFN_D_MASKDONEIRQ;
	int r, cmdi, srci, dsti, resi;

	DPRINTF("%s()\n", __FUNCTION__);

	rc.masks = htole16(2 << 13);
	rc.session_num = htole16(addr >> 14);
	rc.total_source_count = htole16(addr & 0x3fff);
	rc.total_dest_count = htole16(8);

	hifn_alloc_slot(sc, &cmdi, &srci, &dsti, &resi);

	WRITE_REG_1(sc, HIFN_1_DMA_CSR,
	    HIFN_DMACSR_C_CTRL_ENA | HIFN_DMACSR_S_CTRL_ENA |
	    HIFN_DMACSR_D_CTRL_ENA | HIFN_DMACSR_R_CTRL_ENA);

	bzero(dma->command_bufs[cmdi], HIFN_MAX_COMMAND);
	*(hifn_base_command_t *)dma->command_bufs[cmdi] = rc;

	dma->srcr[srci].p = htole32(sc->sc_dma_physaddr +
	    offsetof(struct hifn_dma, test_src));
	dma->test_src = 0;
	dma->dstr[dsti].p =  htole32(sc->sc_dma_physaddr +
	    offsetof(struct hifn_dma, test_dst));
	dma->test_dst = 0;
	dma->cmdr[cmdi].l = htole32(8 | masks);
	dma->srcr[srci].l = htole32(8 | masks);
	dma->dstr[dsti].l = htole32(8 | masks);
	dma->resr[resi].l = htole32(HIFN_MAX_RESULT | masks);

	for (r = 10000; r >= 0; r--) {
		DELAY(10);
		if ((dma->resr[resi].l & htole32(HIFN_D_VALID)) == 0)
			break;
	}
	if (r == 0) {
		device_printf(sc->sc_dev, "readramaddr -- "
		    "result[%d](addr %d) still valid\n", resi, addr);
		r = -1;
	} else {
		r = 0;
		bcopy(&dma->test_dst, data, sizeof(dma->test_dst));
	}

	WRITE_REG_1(sc, HIFN_1_DMA_CSR,
	    HIFN_DMACSR_C_CTRL_DIS | HIFN_DMACSR_S_CTRL_DIS |
	    HIFN_DMACSR_D_CTRL_DIS | HIFN_DMACSR_R_CTRL_DIS);

	return (r);
}

/*
 * Initialize the descriptor rings.
 */
static void 
hifn_init_dma(struct hifn_softc *sc)
{
	struct hifn_dma *dma = sc->sc_dma;
	int i;

	DPRINTF("%s()\n", __FUNCTION__);

	hifn_set_retry(sc);

	/* initialize static pointer values */
	for (i = 0; i < HIFN_D_CMD_RSIZE; i++)
		dma->cmdr[i].p = htole32(sc->sc_dma_physaddr +
		    offsetof(struct hifn_dma, command_bufs[i][0]));
	for (i = 0; i < HIFN_D_RES_RSIZE; i++)
		dma->resr[i].p = htole32(sc->sc_dma_physaddr +
		    offsetof(struct hifn_dma, result_bufs[i][0]));

	dma->cmdr[HIFN_D_CMD_RSIZE].p =
	    htole32(sc->sc_dma_physaddr + offsetof(struct hifn_dma, cmdr[0]));
	dma->srcr[HIFN_D_SRC_RSIZE].p =
	    htole32(sc->sc_dma_physaddr + offsetof(struct hifn_dma, srcr[0]));
	dma->dstr[HIFN_D_DST_RSIZE].p =
	    htole32(sc->sc_dma_physaddr + offsetof(struct hifn_dma, dstr[0]));
	dma->resr[HIFN_D_RES_RSIZE].p =
	    htole32(sc->sc_dma_physaddr + offsetof(struct hifn_dma, resr[0]));

	dma->cmdu = dma->srcu = dma->dstu = dma->resu = 0;
	dma->cmdi = dma->srci = dma->dsti = dma->resi = 0;
	dma->cmdk = dma->srck = dma->dstk = dma->resk = 0;
}

/*
 * Writes out the raw command buffer space.  Returns the
 * command buffer size.
 */
static u_int
hifn_write_command(struct hifn_command *cmd, u_int8_t *buf)
{
	u_int8_t *buf_pos;
	hifn_base_command_t *base_cmd;
	hifn_mac_command_t *mac_cmd;
	hifn_crypt_command_t *cry_cmd;
	int using_mac, using_crypt, len, ivlen;
	u_int32_t dlen, slen;

	DPRINTF("%s()\n", __FUNCTION__);

	buf_pos = buf;
	using_mac = cmd->base_masks & HIFN_BASE_CMD_MAC;
	using_crypt = cmd->base_masks & HIFN_BASE_CMD_CRYPT;

	base_cmd = (hifn_base_command_t *)buf_pos;
	base_cmd->masks = htole16(cmd->base_masks);
	slen = cmd->src_mapsize;
	if (cmd->sloplen)
		dlen = cmd->dst_mapsize - cmd->sloplen + sizeof(u_int32_t);
	else
		dlen = cmd->dst_mapsize;
	base_cmd->total_source_count = htole16(slen & HIFN_BASE_CMD_LENMASK_LO);
	base_cmd->total_dest_count = htole16(dlen & HIFN_BASE_CMD_LENMASK_LO);
	dlen >>= 16;
	slen >>= 16;
	base_cmd->session_num = htole16(
	    ((slen << HIFN_BASE_CMD_SRCLEN_S) & HIFN_BASE_CMD_SRCLEN_M) |
	    ((dlen << HIFN_BASE_CMD_DSTLEN_S) & HIFN_BASE_CMD_DSTLEN_M));
	buf_pos += sizeof(hifn_base_command_t);

	if (using_mac) {
		mac_cmd = (hifn_mac_command_t *)buf_pos;
		dlen = cmd->maccrd->crd_len;
		mac_cmd->source_count = htole16(dlen & 0xffff);
		dlen >>= 16;
		mac_cmd->masks = htole16(cmd->mac_masks |
		    ((dlen << HIFN_MAC_CMD_SRCLEN_S) & HIFN_MAC_CMD_SRCLEN_M));
		mac_cmd->header_skip = htole16(cmd->maccrd->crd_skip);
		mac_cmd->reserved = 0;
		buf_pos += sizeof(hifn_mac_command_t);
	}

	if (using_crypt) {
		cry_cmd = (hifn_crypt_command_t *)buf_pos;
		dlen = cmd->enccrd->crd_len;
		cry_cmd->source_count = htole16(dlen & 0xffff);
		dlen >>= 16;
		cry_cmd->masks = htole16(cmd->cry_masks |
		    ((dlen << HIFN_CRYPT_CMD_SRCLEN_S) & HIFN_CRYPT_CMD_SRCLEN_M));
		cry_cmd->header_skip = htole16(cmd->enccrd->crd_skip);
		cry_cmd->reserved = 0;
		buf_pos += sizeof(hifn_crypt_command_t);
	}

	if (using_mac && cmd->mac_masks & HIFN_MAC_CMD_NEW_KEY) {
		bcopy(cmd->mac, buf_pos, HIFN_MAC_KEY_LENGTH);
		buf_pos += HIFN_MAC_KEY_LENGTH;
	}

	if (using_crypt && cmd->cry_masks & HIFN_CRYPT_CMD_NEW_KEY) {
		switch (cmd->cry_masks & HIFN_CRYPT_CMD_ALG_MASK) {
		case HIFN_CRYPT_CMD_ALG_3DES:
			bcopy(cmd->ck, buf_pos, HIFN_3DES_KEY_LENGTH);
			buf_pos += HIFN_3DES_KEY_LENGTH;
			break;
		case HIFN_CRYPT_CMD_ALG_DES:
			bcopy(cmd->ck, buf_pos, HIFN_DES_KEY_LENGTH);
			buf_pos += HIFN_DES_KEY_LENGTH;
			break;
		case HIFN_CRYPT_CMD_ALG_RC4:
			len = 256;
			do {
				int clen;

				clen = MIN(cmd->cklen, len);
				bcopy(cmd->ck, buf_pos, clen);
				len -= clen;
				buf_pos += clen;
			} while (len > 0);
			bzero(buf_pos, 4);
			buf_pos += 4;
			break;
		case HIFN_CRYPT_CMD_ALG_AES:
			/*
			 * AES keys are variable 128, 192 and
			 * 256 bits (16, 24 and 32 bytes).
			 */
			bcopy(cmd->ck, buf_pos, cmd->cklen);
			buf_pos += cmd->cklen;
			break;
		}
	}

	if (using_crypt && cmd->cry_masks & HIFN_CRYPT_CMD_NEW_IV) {
		switch (cmd->cry_masks & HIFN_CRYPT_CMD_ALG_MASK) {
		case HIFN_CRYPT_CMD_ALG_AES:
			ivlen = HIFN_AES_IV_LENGTH;
			break;
		default:
			ivlen = HIFN_IV_LENGTH;
			break;
		}
		bcopy(cmd->iv, buf_pos, ivlen);
		buf_pos += ivlen;
	}

	if ((cmd->base_masks & (HIFN_BASE_CMD_MAC|HIFN_BASE_CMD_CRYPT)) == 0) {
		bzero(buf_pos, 8);
		buf_pos += 8;
	}

	return (buf_pos - buf);
}

static int
hifn_dmamap_aligned(struct hifn_operand *op)
{
	int i;

	DPRINTF("%s()\n", __FUNCTION__);

	for (i = 0; i < op->nsegs; i++) {
		if (op->segs[i].ds_addr & 3)
			return (0);
		if ((i != (op->nsegs - 1)) && (op->segs[i].ds_len & 3))
			return (0);
	}
	return (1);
}

static int
hifn_dmamap_load_dst(struct hifn_softc *sc, struct hifn_command *cmd)
{
	struct hifn_dma *dma = sc->sc_dma;
	struct hifn_operand *dst = &cmd->dst;
	u_int32_t p, l;
	int idx, used = 0, i;

	DPRINTF("%s()\n", __FUNCTION__);

	idx = dma->dsti;
	for (i = 0; i < dst->nsegs - 1; i++) {
		dma->dstr[idx].p = htole32(dst->segs[i].ds_addr);
		dma->dstr[idx].l = htole32(HIFN_D_MASKDONEIRQ | dst->segs[i].ds_len);
		wmb();
		dma->dstr[idx].l |= htole32(HIFN_D_VALID);
		HIFN_DSTR_SYNC(sc, idx,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		used++;

		if (++idx == HIFN_D_DST_RSIZE) {
			dma->dstr[idx].l = htole32(HIFN_D_JUMP | HIFN_D_MASKDONEIRQ);
			wmb();
			dma->dstr[idx].l |= htole32(HIFN_D_VALID);
			HIFN_DSTR_SYNC(sc, idx,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
			idx = 0;
		}
	}

	if (cmd->sloplen == 0) {
		p = dst->segs[i].ds_addr;
		l = HIFN_D_MASKDONEIRQ | HIFN_D_LAST |
		    dst->segs[i].ds_len;
	} else {
		p = sc->sc_dma_physaddr +
		    offsetof(struct hifn_dma, slop[cmd->slopidx]);
		l = HIFN_D_MASKDONEIRQ | HIFN_D_LAST |
		    sizeof(u_int32_t);

		if ((dst->segs[i].ds_len - cmd->sloplen) != 0) {
			dma->dstr[idx].p = htole32(dst->segs[i].ds_addr);
			dma->dstr[idx].l = htole32(HIFN_D_MASKDONEIRQ |
			    (dst->segs[i].ds_len - cmd->sloplen));
			wmb();
			dma->dstr[idx].l |= htole32(HIFN_D_VALID);
			HIFN_DSTR_SYNC(sc, idx,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
			used++;

			if (++idx == HIFN_D_DST_RSIZE) {
				dma->dstr[idx].l = htole32(HIFN_D_JUMP | HIFN_D_MASKDONEIRQ);
				wmb();
				dma->dstr[idx].l |= htole32(HIFN_D_VALID);
				HIFN_DSTR_SYNC(sc, idx,
				    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
				idx = 0;
			}
		}
	}
	dma->dstr[idx].p = htole32(p);
	dma->dstr[idx].l = htole32(l);
	wmb();
	dma->dstr[idx].l |= htole32(HIFN_D_VALID);
	HIFN_DSTR_SYNC(sc, idx, BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	used++;

	if (++idx == HIFN_D_DST_RSIZE) {
		dma->dstr[idx].l = htole32(HIFN_D_JUMP | HIFN_D_MASKDONEIRQ);
		wmb();
		dma->dstr[idx].l |= htole32(HIFN_D_VALID);
		HIFN_DSTR_SYNC(sc, idx,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		idx = 0;
	}

	dma->dsti = idx;
	dma->dstu += used;
	return (idx);
}

static int
hifn_dmamap_load_src(struct hifn_softc *sc, struct hifn_command *cmd)
{
	struct hifn_dma *dma = sc->sc_dma;
	struct hifn_operand *src = &cmd->src;
	int idx, i;
	u_int32_t last = 0;

	DPRINTF("%s()\n", __FUNCTION__);

	idx = dma->srci;
	for (i = 0; i < src->nsegs; i++) {
		if (i == src->nsegs - 1)
			last = HIFN_D_LAST;

		dma->srcr[idx].p = htole32(src->segs[i].ds_addr);
		dma->srcr[idx].l = htole32(src->segs[i].ds_len |
		    HIFN_D_MASKDONEIRQ | last);
		wmb();
		dma->srcr[idx].l |= htole32(HIFN_D_VALID);
		HIFN_SRCR_SYNC(sc, idx,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);

		if (++idx == HIFN_D_SRC_RSIZE) {
			dma->srcr[idx].l = htole32(HIFN_D_JUMP | HIFN_D_MASKDONEIRQ);
			wmb();
			dma->srcr[idx].l |= htole32(HIFN_D_VALID);
			HIFN_SRCR_SYNC(sc, HIFN_D_SRC_RSIZE,
			    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
			idx = 0;
		}
	}
	dma->srci = idx;
	dma->srcu += src->nsegs;
	return (idx);
} 


static int 
hifn_crypto(
	struct hifn_softc *sc,
	struct hifn_command *cmd,
	struct cryptop *crp,
	int hint)
{
	struct	hifn_dma *dma = sc->sc_dma;
	u_int32_t cmdlen;
	int cmdi, resi, err = 0;
	unsigned long l_flags;

	DPRINTF("%s()\n", __FUNCTION__);

	/*
	 * need 1 cmd, and 1 res
	 *
	 * NB: check this first since it's easy.
	 */
	HIFN_LOCK(sc);
	if ((dma->cmdu + 1) > HIFN_D_CMD_RSIZE ||
	    (dma->resu + 1) > HIFN_D_RES_RSIZE) {
#ifdef HIFN_DEBUG
		if (hifn_debug) {
			device_printf(sc->sc_dev,
				"cmd/result exhaustion, cmdu %u resu %u\n",
				dma->cmdu, dma->resu);
		}
#endif
		hifnstats.hst_nomem_cr++;
		HIFN_UNLOCK(sc);
		return (ERESTART);
	}

	if (crp->crp_flags & CRYPTO_F_SKBUF) {
		if (pci_map_skb(sc, &cmd->src, cmd->src_skb)) {
			hifnstats.hst_nomem_load++;
			err = ENOMEM;
			goto err_srcmap1;
		}
	} else if (crp->crp_flags & CRYPTO_F_IOV) {
		if (pci_map_uio(sc, &cmd->src, cmd->src_io)) {
			hifnstats.hst_nomem_load++;
			err = ENOMEM;
			goto err_srcmap1;
		}
	} else {
		if (pci_map_buf(sc, &cmd->src, cmd->src_buf, crp->crp_ilen)) {
			hifnstats.hst_nomem_load++;
			err = ENOMEM;
			goto err_srcmap1;
		}
	}

	if (hifn_dmamap_aligned(&cmd->src)) {
		cmd->sloplen = cmd->src_mapsize & 3;
		cmd->dst = cmd->src;
	} else {
		if (crp->crp_flags & CRYPTO_F_IOV) {
			DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
			err = EINVAL;
			goto err_srcmap;
		} else if (crp->crp_flags & CRYPTO_F_SKBUF) {
#ifdef NOTYET
			int totlen, len;
			struct mbuf *m, *m0, *mlast;

			KASSERT(cmd->dst_m == cmd->src_m,
				("hifn_crypto: dst_m initialized improperly"));
			hifnstats.hst_unaligned++;
			/*
			 * Source is not aligned on a longword boundary.
			 * Copy the data to insure alignment.  If we fail
			 * to allocate mbufs or clusters while doing this
			 * we return ERESTART so the operation is requeued
			 * at the crypto later, but only if there are
			 * ops already posted to the hardware; otherwise we
			 * have no guarantee that we'll be re-entered.
			 */
			totlen = cmd->src_mapsize;
			if (cmd->src_m->m_flags & M_PKTHDR) {
				len = MHLEN;
				MGETHDR(m0, M_DONTWAIT, MT_DATA);
				if (m0 && !m_dup_pkthdr(m0, cmd->src_m, M_DONTWAIT)) {
					m_free(m0);
					m0 = NULL;
				}
			} else {
				len = MLEN;
				MGET(m0, M_DONTWAIT, MT_DATA);
			}
			if (m0 == NULL) {
				hifnstats.hst_nomem_mbuf++;
				err = dma->cmdu ? ERESTART : ENOMEM;
				goto err_srcmap;
			}
			if (totlen >= MINCLSIZE) {
				MCLGET(m0, M_DONTWAIT);
				if ((m0->m_flags & M_EXT) == 0) {
					hifnstats.hst_nomem_mcl++;
					err = dma->cmdu ? ERESTART : ENOMEM;
					m_freem(m0);
					goto err_srcmap;
				}
				len = MCLBYTES;
			}
			totlen -= len;
			m0->m_pkthdr.len = m0->m_len = len;
			mlast = m0;

			while (totlen > 0) {
				MGET(m, M_DONTWAIT, MT_DATA);
				if (m == NULL) {
					hifnstats.hst_nomem_mbuf++;
					err = dma->cmdu ? ERESTART : ENOMEM;
					m_freem(m0);
					goto err_srcmap;
				}
				len = MLEN;
				if (totlen >= MINCLSIZE) {
					MCLGET(m, M_DONTWAIT);
					if ((m->m_flags & M_EXT) == 0) {
						hifnstats.hst_nomem_mcl++;
						err = dma->cmdu ? ERESTART : ENOMEM;
						mlast->m_next = m;
						m_freem(m0);
						goto err_srcmap;
					}
					len = MCLBYTES;
				}

				m->m_len = len;
				m0->m_pkthdr.len += len;
				totlen -= len;

				mlast->m_next = m;
				mlast = m;
			}
			cmd->dst_m = m0;
#else
			device_printf(sc->sc_dev,
					"%s,%d: CRYPTO_F_SKBUF unaligned not implemented\n",
					__FILE__, __LINE__);
			err = EINVAL;
			goto err_srcmap;
#endif
		} else {
			device_printf(sc->sc_dev,
					"%s,%d: unaligned contig buffers not implemented\n",
					__FILE__, __LINE__);
			err = EINVAL;
			goto err_srcmap;
		}
	}

	if (cmd->dst_map == NULL) {
		if (crp->crp_flags & CRYPTO_F_SKBUF) {
			if (pci_map_skb(sc, &cmd->dst, cmd->dst_skb)) {
				hifnstats.hst_nomem_map++;
				err = ENOMEM;
				goto err_dstmap1;
			}
		} else if (crp->crp_flags & CRYPTO_F_IOV) {
			if (pci_map_uio(sc, &cmd->dst, cmd->dst_io)) {
				hifnstats.hst_nomem_load++;
				err = ENOMEM;
				goto err_dstmap1;
			}
		} else {
			if (pci_map_buf(sc, &cmd->dst, cmd->dst_buf, crp->crp_ilen)) {
				hifnstats.hst_nomem_load++;
				err = ENOMEM;
				goto err_dstmap1;
			}
		}
	}

#ifdef HIFN_DEBUG
	if (hifn_debug) {
		device_printf(sc->sc_dev,
		    "Entering cmd: stat %8x ien %8x u %d/%d/%d/%d n %d/%d\n",
		    READ_REG_1(sc, HIFN_1_DMA_CSR),
		    READ_REG_1(sc, HIFN_1_DMA_IER),
		    dma->cmdu, dma->srcu, dma->dstu, dma->resu,
		    cmd->src_nsegs, cmd->dst_nsegs);
	}
#endif

#if 0
	if (cmd->src_map == cmd->dst_map) {
		bus_dmamap_sync(sc->sc_dmat, cmd->src_map,
		    BUS_DMASYNC_PREWRITE|BUS_DMASYNC_PREREAD);
	} else {
		bus_dmamap_sync(sc->sc_dmat, cmd->src_map,
		    BUS_DMASYNC_PREWRITE);
		bus_dmamap_sync(sc->sc_dmat, cmd->dst_map,
		    BUS_DMASYNC_PREREAD);
	}
#endif

	/*
	 * need N src, and N dst
	 */
	if ((dma->srcu + cmd->src_nsegs) > HIFN_D_SRC_RSIZE ||
	    (dma->dstu + cmd->dst_nsegs + 1) > HIFN_D_DST_RSIZE) {
#ifdef HIFN_DEBUG
		if (hifn_debug) {
			device_printf(sc->sc_dev,
				"src/dst exhaustion, srcu %u+%u dstu %u+%u\n",
				dma->srcu, cmd->src_nsegs,
				dma->dstu, cmd->dst_nsegs);
		}
#endif
		hifnstats.hst_nomem_sd++;
		err = ERESTART;
		goto err_dstmap;
	}

	if (dma->cmdi == HIFN_D_CMD_RSIZE) {
		dma->cmdi = 0;
		dma->cmdr[HIFN_D_CMD_RSIZE].l = htole32(HIFN_D_JUMP|HIFN_D_MASKDONEIRQ);
		wmb();
		dma->cmdr[HIFN_D_CMD_RSIZE].l |= htole32(HIFN_D_VALID);
		HIFN_CMDR_SYNC(sc, HIFN_D_CMD_RSIZE,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	}
	cmdi = dma->cmdi++;
	cmdlen = hifn_write_command(cmd, dma->command_bufs[cmdi]);
	HIFN_CMD_SYNC(sc, cmdi, BUS_DMASYNC_PREWRITE);

	/* .p for command/result already set */
	dma->cmdr[cmdi].l = htole32(cmdlen | HIFN_D_LAST |
	    HIFN_D_MASKDONEIRQ);
	wmb();
	dma->cmdr[cmdi].l |= htole32(HIFN_D_VALID);
	HIFN_CMDR_SYNC(sc, cmdi,
	    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	dma->cmdu++;
	if (sc->sc_c_busy == 0) {
		WRITE_REG_1(sc, HIFN_1_DMA_CSR, HIFN_DMACSR_C_CTRL_ENA);
		sc->sc_c_busy = 1;
	}

	/*
	 * We don't worry about missing an interrupt (which a "command wait"
	 * interrupt salvages us from), unless there is more than one command
	 * in the queue.
	 */
	if (dma->cmdu > 1) {
		sc->sc_dmaier |= HIFN_DMAIER_C_WAIT;
		WRITE_REG_1(sc, HIFN_1_DMA_IER, sc->sc_dmaier);
	}

	hifnstats.hst_ipackets++;
	hifnstats.hst_ibytes += cmd->src_mapsize;

	hifn_dmamap_load_src(sc, cmd);
	if (sc->sc_s_busy == 0) {
		WRITE_REG_1(sc, HIFN_1_DMA_CSR, HIFN_DMACSR_S_CTRL_ENA);
		sc->sc_s_busy = 1;
	}

	/*
	 * Unlike other descriptors, we don't mask done interrupt from
	 * result descriptor.
	 */
#ifdef HIFN_DEBUG
	if (hifn_debug)
		device_printf(sc->sc_dev, "load res\n");
#endif
	if (dma->resi == HIFN_D_RES_RSIZE) {
		dma->resi = 0;
		dma->resr[HIFN_D_RES_RSIZE].l = htole32(HIFN_D_JUMP|HIFN_D_MASKDONEIRQ);
		wmb();
		dma->resr[HIFN_D_RES_RSIZE].l |= htole32(HIFN_D_VALID);
		HIFN_RESR_SYNC(sc, HIFN_D_RES_RSIZE,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}
	resi = dma->resi++;
	KASSERT(dma->hifn_commands[resi] == NULL,
		("hifn_crypto: command slot %u busy", resi));
	dma->hifn_commands[resi] = cmd;
	HIFN_RES_SYNC(sc, resi, BUS_DMASYNC_PREREAD);
	if ((hint & CRYPTO_HINT_MORE) && sc->sc_curbatch < hifn_maxbatch) {
		dma->resr[resi].l = htole32(HIFN_MAX_RESULT |
		    HIFN_D_LAST | HIFN_D_MASKDONEIRQ);
		wmb();
		dma->resr[resi].l |= htole32(HIFN_D_VALID);
		sc->sc_curbatch++;
		if (sc->sc_curbatch > hifnstats.hst_maxbatch)
			hifnstats.hst_maxbatch = sc->sc_curbatch;
		hifnstats.hst_totbatch++;
	} else {
		dma->resr[resi].l = htole32(HIFN_MAX_RESULT | HIFN_D_LAST);
		wmb();
		dma->resr[resi].l |= htole32(HIFN_D_VALID);
		sc->sc_curbatch = 0;
	}
	HIFN_RESR_SYNC(sc, resi,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	dma->resu++;
	if (sc->sc_r_busy == 0) {
		WRITE_REG_1(sc, HIFN_1_DMA_CSR, HIFN_DMACSR_R_CTRL_ENA);
		sc->sc_r_busy = 1;
	}

	if (cmd->sloplen)
		cmd->slopidx = resi;

	hifn_dmamap_load_dst(sc, cmd);

	if (sc->sc_d_busy == 0) {
		WRITE_REG_1(sc, HIFN_1_DMA_CSR, HIFN_DMACSR_D_CTRL_ENA);
		sc->sc_d_busy = 1;
	}

#ifdef HIFN_DEBUG
	if (hifn_debug) {
		device_printf(sc->sc_dev, "command: stat %8x ier %8x\n",
		    READ_REG_1(sc, HIFN_1_DMA_CSR),
		    READ_REG_1(sc, HIFN_1_DMA_IER));
	}
#endif

	sc->sc_active = 5;
	HIFN_UNLOCK(sc);
	KASSERT(err == 0, ("hifn_crypto: success with error %u", err));
	return (err);		/* success */

err_dstmap:
	if (cmd->src_map != cmd->dst_map)
		pci_unmap_buf(sc, &cmd->dst);
err_dstmap1:
err_srcmap:
	if (crp->crp_flags & CRYPTO_F_SKBUF) {
		if (cmd->src_skb != cmd->dst_skb)
#ifdef NOTYET
			m_freem(cmd->dst_m);
#else
			device_printf(sc->sc_dev,
					"%s,%d: CRYPTO_F_SKBUF src != dst not implemented\n",
					__FILE__, __LINE__);
#endif
	}
	pci_unmap_buf(sc, &cmd->src);
err_srcmap1:
	HIFN_UNLOCK(sc);
	return (err);
}

/*
 * hifn_tick - timer to check for errors in DMA rings
 *
 * @arg - hifn chip number to process.
 *
 * This function checks if the chip was active, and if so, checks the
 * rings to see if there is a situation with the rings that might concern us
 * and adjusts the status of things, and then disables appropriate DMA engines.
 *
 * This function is seperate from hifn_pk_timeout because of the difference in
 * timing, and a desire to isolate the two functions a bit more.
 *
 */
static void
hifn_tick(unsigned long arg)
{
	struct hifn_softc *sc;
	unsigned long l_flags;

	if (arg >= HIFN_MAX_CHIPS)
		return;
	sc = hifn_chip_idx[arg];
	if (!sc)
		return;

	HIFN_LOCK(sc);
	if (sc->sc_active == 0) {
		struct hifn_dma *dma = sc->sc_dma;
		u_int32_t r = 0;

		if (dma->cmdu == 0 && sc->sc_c_busy) {
			sc->sc_c_busy = 0;
			r |= HIFN_DMACSR_C_CTRL_DIS;
		}
		if (dma->srcu == 0 && sc->sc_s_busy) {
			sc->sc_s_busy = 0;
			r |= HIFN_DMACSR_S_CTRL_DIS;
		}
		if (dma->dstu == 0 && sc->sc_d_busy) {
			sc->sc_d_busy = 0;
			r |= HIFN_DMACSR_D_CTRL_DIS;
		}
		if (dma->resu == 0 && sc->sc_r_busy) {
			sc->sc_r_busy = 0;
			r |= HIFN_DMACSR_R_CTRL_DIS;
		}
		if (r)
			WRITE_REG_1(sc, HIFN_1_DMA_CSR, r);
	} else
		sc->sc_active--;
	HIFN_UNLOCK(sc);
	mod_timer(&sc->sc_tickto, jiffies + HZ);
}

static irqreturn_t
hifn_intr(int irq, void *arg, struct pt_regs *regs)
{
	struct hifn_softc *sc = arg;
	struct hifn_dma *dma;
	u_int32_t dmacsr, restart;
	int i, u;
	unsigned long l_flags;

	dmacsr = READ_REG_1(sc, HIFN_1_DMA_CSR);

	/* Nothing in the DMA unit interrupted */
	if ((dmacsr & sc->sc_dmaier) == 0)
		return IRQ_NONE;

	HIFN_LOCK(sc);

	dma = sc->sc_dma;

#ifdef HIFN_DEBUG
	if (hifn_debug) {
		device_printf(sc->sc_dev,
		    "irq: stat %08x ien %08x damier %08x i %d/%d/%d/%d k %d/%d/%d/%d u %d/%d/%d/%d\n",
		    dmacsr, READ_REG_1(sc, HIFN_1_DMA_IER), sc->sc_dmaier,
		    dma->cmdi, dma->srci, dma->dsti, dma->resi,
		    dma->cmdk, dma->srck, dma->dstk, dma->resk,
		    dma->cmdu, dma->srcu, dma->dstu, dma->resu);
	}
#endif

	/* clear interrupts that were true */
	WRITE_REG_1(sc, HIFN_1_DMA_CSR, dmacsr & sc->sc_dmaier);

#if !defined(CONFIG_OCF_HIFN_PKMMAP)
	/* check out public key engine, if there is one */
	if ((sc->sc_flags & HIFN_HAS_PUBLIC) &&
	    (dmacsr & HIFN_DMACSR_PUBDONE)) {
		
		/* clear DONE bit */
		WRITE_REG_1(sc, HIFN_1_PUB_STATUS,
		    READ_REG_1(sc, HIFN_1_PUB_STATUS) | HIFN_PUBSTS_DONE);

		hifn_kintr(sc);
	}
#endif

	restart = dmacsr & (HIFN_DMACSR_D_OVER | HIFN_DMACSR_R_OVER);
	if (restart)
		device_printf(sc->sc_dev, "overrun %x\n", dmacsr);

	if (sc->sc_flags & HIFN_IS_7811) {
		if (dmacsr & HIFN_DMACSR_ILLR)
			device_printf(sc->sc_dev, "illegal read\n");
		if (dmacsr & HIFN_DMACSR_ILLW)
			device_printf(sc->sc_dev, "illegal write\n");
	}

	restart = dmacsr & (HIFN_DMACSR_C_ABORT | HIFN_DMACSR_S_ABORT |
	    HIFN_DMACSR_D_ABORT | HIFN_DMACSR_R_ABORT);
	if (restart) {
		device_printf(sc->sc_dev, "abort, resetting.\n");
		hifnstats.hst_abort++;
		hifn_abort(sc);
		HIFN_UNLOCK(sc);
		return IRQ_HANDLED;
	}

	if ((dmacsr & HIFN_DMACSR_C_WAIT) && (dma->cmdu == 0)) {
		/*
		 * If no slots to process and we receive a "waiting on
		 * command" interrupt, we disable the "waiting on command"
		 * (by clearing it).
		 */
		sc->sc_dmaier &= ~HIFN_DMAIER_C_WAIT;
		WRITE_REG_1(sc, HIFN_1_DMA_IER, sc->sc_dmaier);
	}

	/* clear the rings */
	i = dma->resk; u = dma->resu;
	while (u != 0) {
		HIFN_RESR_SYNC(sc, i,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		if (dma->resr[i].l & htole32(HIFN_D_VALID)) {
			HIFN_RESR_SYNC(sc, i,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
			break;
		}

		if (i != HIFN_D_RES_RSIZE) {
			struct hifn_command *cmd;
			u_int8_t *macbuf = NULL;

			HIFN_RES_SYNC(sc, i, BUS_DMASYNC_POSTREAD);
			cmd = dma->hifn_commands[i];
			KASSERT(cmd != NULL,
				("hifn_intr: null command slot %u", i));
			dma->hifn_commands[i] = NULL;

			if (cmd->base_masks & HIFN_BASE_CMD_MAC) {
				macbuf = dma->result_bufs[i];
				macbuf += 12;
			}

			hifn_callback(sc, cmd, macbuf);
			hifnstats.hst_opackets++;
			u--;
		}

		if (++i == (HIFN_D_RES_RSIZE + 1))
			i = 0;
	}
	dma->resk = i; dma->resu = u;

	i = dma->srck; u = dma->srcu;
	while (u != 0) {
		if (i == HIFN_D_SRC_RSIZE)
			i = 0;
		HIFN_SRCR_SYNC(sc, i,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		if (dma->srcr[i].l & htole32(HIFN_D_VALID)) {
			HIFN_SRCR_SYNC(sc, i,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
			break;
		}
		i++, u--;
	}
	dma->srck = i; dma->srcu = u;

	i = dma->cmdk; u = dma->cmdu;
	while (u != 0) {
		HIFN_CMDR_SYNC(sc, i,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		if (dma->cmdr[i].l & htole32(HIFN_D_VALID)) {
			HIFN_CMDR_SYNC(sc, i,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
			break;
		}
		if (i != HIFN_D_CMD_RSIZE) {
			u--;
			HIFN_CMD_SYNC(sc, i, BUS_DMASYNC_POSTWRITE);
		}
		if (++i == (HIFN_D_CMD_RSIZE + 1))
			i = 0;
	}
	dma->cmdk = i; dma->cmdu = u;

	HIFN_UNLOCK(sc);

	if (sc->sc_needwakeup) {		/* XXX check high watermark */
		int wakeup = sc->sc_needwakeup & (CRYPTO_SYMQ|CRYPTO_ASYMQ);
#ifdef HIFN_DEBUG
		if (hifn_debug)
			device_printf(sc->sc_dev,
				"wakeup crypto (%x) u %d/%d/%d/%d\n",
				sc->sc_needwakeup,
				dma->cmdu, dma->srcu, dma->dstu, dma->resu);
#endif
		sc->sc_needwakeup &= ~wakeup;
		crypto_unblock(sc->sc_cid, wakeup);
	}

	return IRQ_HANDLED;
}

/*
 * Allocate a new 'session' and return an encoded session id.  'sidp'
 * contains our registration id, and should contain an encoded session
 * id on successful allocation.
 */
static int
hifn_newsession(void *arg, u_int32_t *sidp, struct cryptoini *cri)
{
	struct cryptoini *c;
	struct hifn_softc *sc = arg;
	int mac = 0, cry = 0, sesn;
	struct hifn_session *ses = NULL;

	DPRINTF("%s()\n", __FUNCTION__);

	KASSERT(sc != NULL, ("hifn_newsession: null softc"));
	if (sidp == NULL || cri == NULL || sc == NULL) {
		DPRINTF("%s,%d: %s - EINVAL\n", __FILE__, __LINE__, __FUNCTION__);
		return (EINVAL);
	}

	if (sc->sc_sessions == NULL) {
		ses = sc->sc_sessions = (struct hifn_session *)kmalloc(sizeof(*ses),
				GFP_ATOMIC);
		if (ses == NULL)
			return (ENOMEM);
		sesn = 0;
		sc->sc_nsessions = 1;
	} else {
		for (sesn = 0; sesn < sc->sc_nsessions; sesn++) {
			if (!sc->sc_sessions[sesn].hs_used) {
				ses = &sc->sc_sessions[sesn];
				break;
			}
		}

		if (ses == NULL) {
			sesn = sc->sc_nsessions;
			ses = (struct hifn_session *)kmalloc((sesn + 1) * sizeof(*ses),
					GFP_ATOMIC);
			if (ses == NULL)
				return (ENOMEM);
			bcopy(sc->sc_sessions, ses, sesn * sizeof(*ses));
			bzero(sc->sc_sessions, sesn * sizeof(*ses));
			kfree(sc->sc_sessions);
			sc->sc_sessions = ses;
			ses = &sc->sc_sessions[sesn];
			sc->sc_nsessions++;
		}
	}
	bzero(ses, sizeof(*ses));
	ses->hs_used = 1;

	for (c = cri; c != NULL; c = c->cri_next) {
		switch (c->cri_alg) {
		case CRYPTO_MD5:
		case CRYPTO_SHA1:
		case CRYPTO_MD5_HMAC:
		case CRYPTO_SHA1_HMAC:
			if (mac) {
				DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
				return (EINVAL);
			}
			mac = 1;
			break;
		case CRYPTO_DES_CBC:
		case CRYPTO_3DES_CBC:
		case CRYPTO_AES_CBC:
			/* XXX this may read fewer, does it matter? */
			read_random(ses->hs_iv,
				c->cri_alg == CRYPTO_AES_CBC ?
					HIFN_AES_IV_LENGTH : HIFN_IV_LENGTH);
			/*FALLTHROUGH*/
		case CRYPTO_ARC4:
			if (cry) {
				DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
				return (EINVAL);
			}
			cry = 1;
			break;
		default:
			DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
			return (EINVAL);
		}
	}
	if (mac == 0 && cry == 0) {
		DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
		return (EINVAL);
	}

	*sidp = HIFN_SID(sc->sc_num, sesn);

	return (0);
}

/*
 * Deallocate a session.
 * XXX this routine should run a zero'd mac/encrypt key into context ram.
 * XXX to blow away any keys already stored there.
 */
static int
hifn_freesession(void *arg, u_int64_t tid)
{
	struct hifn_softc *sc = arg;
	int session;
	u_int32_t sid = CRYPTO_SESID2LID(tid);

	DPRINTF("%s()\n", __FUNCTION__);

	KASSERT(sc != NULL, ("hifn_freesession: null softc"));
	if (sc == NULL) {
		DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
		return (EINVAL);
	}

	session = HIFN_SESSION(sid);
	if (session >= sc->sc_nsessions) {
		DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
		return (EINVAL);
	}

	bzero(&sc->sc_sessions[session], sizeof(sc->sc_sessions[session]));
	return (0);
}

static int
hifn_process(void *arg, struct cryptop *crp, int hint)
{
	struct hifn_softc *sc = arg;
	struct hifn_command *cmd = NULL;
	int session, err, ivlen;
	struct cryptodesc *crd1, *crd2, *maccrd, *enccrd;

	DPRINTF("%s()\n", __FUNCTION__);

	if (crp == NULL || crp->crp_callback == NULL) {
		hifnstats.hst_invalid++;
		DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
		return (EINVAL);
	}
	session = HIFN_SESSION(crp->crp_sid);

	if (sc == NULL || session >= sc->sc_nsessions) {
		DPRINTF("%s,%d: %s - EINVAL sc=%p session=%u\n",__FILE__,__LINE__,__FUNCTION__, sc, session);
		err = EINVAL;
		goto errout;
	}

	cmd = kmalloc(sizeof(struct hifn_command), GFP_ATOMIC);
	if (cmd == NULL) {
		hifnstats.hst_nomem++;
		err = ENOMEM;
		goto errout;
	}
	memset(cmd, 0, sizeof(*cmd));

	if (crp->crp_flags & CRYPTO_F_SKBUF) {
		cmd->src_skb = (struct sk_buff *)crp->crp_buf;
		cmd->dst_skb = (struct sk_buff *)crp->crp_buf;
	} else if (crp->crp_flags & CRYPTO_F_IOV) {
		cmd->src_io = (struct uio *)crp->crp_buf;
		cmd->dst_io = (struct uio *)crp->crp_buf;
	} else {
		cmd->src_buf = crp->crp_buf;
		cmd->dst_buf = crp->crp_buf;
	}

	crd1 = crp->crp_desc;
	if (crd1 == NULL) {
		DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
		err = EINVAL;
		goto errout;
	}
	crd2 = crd1->crd_next;

	if (crd2 == NULL) {
		if (crd1->crd_alg == CRYPTO_MD5_HMAC ||
		    crd1->crd_alg == CRYPTO_SHA1_HMAC ||
		    crd1->crd_alg == CRYPTO_SHA1 ||
		    crd1->crd_alg == CRYPTO_MD5) {
			maccrd = crd1;
			enccrd = NULL;
		} else if (crd1->crd_alg == CRYPTO_DES_CBC ||
		    crd1->crd_alg == CRYPTO_3DES_CBC ||
		    crd1->crd_alg == CRYPTO_AES_CBC ||
		    crd1->crd_alg == CRYPTO_ARC4) {
			if ((crd1->crd_flags & CRD_F_ENCRYPT) == 0)
				cmd->base_masks |= HIFN_BASE_CMD_DECODE;
			maccrd = NULL;
			enccrd = crd1;
		} else {
			DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
			err = EINVAL;
			goto errout;
		}
	} else {
		if ((crd1->crd_alg == CRYPTO_MD5_HMAC ||
                     crd1->crd_alg == CRYPTO_SHA1_HMAC ||
                     crd1->crd_alg == CRYPTO_MD5 ||
                     crd1->crd_alg == CRYPTO_SHA1) &&
		    (crd2->crd_alg == CRYPTO_DES_CBC ||
		     crd2->crd_alg == CRYPTO_3DES_CBC ||
		     crd2->crd_alg == CRYPTO_AES_CBC ||
		     crd2->crd_alg == CRYPTO_ARC4) &&
		    ((crd2->crd_flags & CRD_F_ENCRYPT) == 0)) {
			cmd->base_masks = HIFN_BASE_CMD_DECODE;
			maccrd = crd1;
			enccrd = crd2;
		} else if ((crd1->crd_alg == CRYPTO_DES_CBC ||
		     crd1->crd_alg == CRYPTO_ARC4 ||
		     crd1->crd_alg == CRYPTO_3DES_CBC ||
		     crd1->crd_alg == CRYPTO_AES_CBC) &&
		    (crd2->crd_alg == CRYPTO_MD5_HMAC ||
                     crd2->crd_alg == CRYPTO_SHA1_HMAC ||
                     crd2->crd_alg == CRYPTO_MD5 ||
                     crd2->crd_alg == CRYPTO_SHA1) &&
		    (crd1->crd_flags & CRD_F_ENCRYPT)) {
			enccrd = crd1;
			maccrd = crd2;
		} else {
			/*
			 * We cannot order the 7751 as requested
			 */
			DPRINTF("%s,%d: %s %d,%d,%d - EINVAL\n",__FILE__,__LINE__,__FUNCTION__, crd1->crd_alg, crd2->crd_alg, crd1->crd_flags & CRD_F_ENCRYPT);
			err = EINVAL;
			goto errout;
		}
	}

	if (enccrd) {
		cmd->enccrd = enccrd;
		cmd->base_masks |= HIFN_BASE_CMD_CRYPT;
		switch (enccrd->crd_alg) {
		case CRYPTO_ARC4:
			cmd->cry_masks |= HIFN_CRYPT_CMD_ALG_RC4;
			break;
		case CRYPTO_DES_CBC:
			cmd->cry_masks |= HIFN_CRYPT_CMD_ALG_DES |
			    HIFN_CRYPT_CMD_MODE_CBC |
			    HIFN_CRYPT_CMD_NEW_IV;
			break;
		case CRYPTO_3DES_CBC:
			cmd->cry_masks |= HIFN_CRYPT_CMD_ALG_3DES |
			    HIFN_CRYPT_CMD_MODE_CBC |
			    HIFN_CRYPT_CMD_NEW_IV;
			break;
		case CRYPTO_AES_CBC:
			cmd->cry_masks |= HIFN_CRYPT_CMD_ALG_AES |
			    HIFN_CRYPT_CMD_MODE_CBC |
			    HIFN_CRYPT_CMD_NEW_IV;
			break;
		default:
			DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
			err = EINVAL;
			goto errout;
		}
		if (enccrd->crd_alg != CRYPTO_ARC4) {
			ivlen = ((enccrd->crd_alg == CRYPTO_AES_CBC) ?
				HIFN_AES_IV_LENGTH : HIFN_IV_LENGTH);
			if (enccrd->crd_flags & CRD_F_ENCRYPT) {
				if (enccrd->crd_flags & CRD_F_IV_EXPLICIT)
					bcopy(enccrd->crd_iv, cmd->iv, ivlen);
				else
					bcopy(sc->sc_sessions[session].hs_iv,
					    cmd->iv, ivlen);

				if ((enccrd->crd_flags & CRD_F_IV_PRESENT)
				    == 0) {
					if (crp->crp_flags & CRYPTO_F_SKBUF)
						skb_copy_bits_back(cmd->src_skb, enccrd->crd_inject,
							(caddr_t)cmd->iv, ivlen);
					else if (crp->crp_flags & CRYPTO_F_IOV)
						cuio_copyback(cmd->src_io,
						    enccrd->crd_inject,
						    ivlen, cmd->iv);
					else
						bcopy(cmd->iv, cmd->src_buf+enccrd->crd_inject, ivlen);
				}
			} else {
				if (enccrd->crd_flags & CRD_F_IV_EXPLICIT)
					bcopy(enccrd->crd_iv, cmd->iv, ivlen);
				else if (crp->crp_flags & CRYPTO_F_SKBUF)
					skb_copy_bits(cmd->src_skb, enccrd->crd_inject,
						(caddr_t)cmd->iv, ivlen);
				else if (crp->crp_flags & CRYPTO_F_IOV)
					cuio_copydata(cmd->src_io,
					    enccrd->crd_inject, ivlen, cmd->iv);
				else
					bcopy(cmd->src_buf + enccrd->crd_inject, cmd->iv, ivlen);
			}
		}

		if (enccrd->crd_flags & CRD_F_KEY_EXPLICIT)
			cmd->cry_masks |= HIFN_CRYPT_CMD_NEW_KEY;
		cmd->ck = enccrd->crd_key;
		cmd->cklen = enccrd->crd_klen >> 3;
		cmd->cry_masks |= HIFN_CRYPT_CMD_NEW_KEY;

		/* 
		 * Need to specify the size for the AES key in the masks.
		 */
		if ((cmd->cry_masks & HIFN_CRYPT_CMD_ALG_MASK) ==
		    HIFN_CRYPT_CMD_ALG_AES) {
			switch (cmd->cklen) {
			case 16:
				cmd->cry_masks |= HIFN_CRYPT_CMD_KSZ_128;
				break;
			case 24:
				cmd->cry_masks |= HIFN_CRYPT_CMD_KSZ_192;
				break;
			case 32:
				cmd->cry_masks |= HIFN_CRYPT_CMD_KSZ_256;
				break;
			default:
				DPRINTF("%s,%d: %s - EINVAL\n",__FILE__,__LINE__,__FUNCTION__);
				err = EINVAL;
				goto errout;
			}
		}
	}

	if (maccrd) {
		cmd->maccrd = maccrd;
		cmd->base_masks |= HIFN_BASE_CMD_MAC;

		switch (maccrd->crd_alg) {
		case CRYPTO_MD5:
			cmd->mac_masks |= HIFN_MAC_CMD_ALG_MD5 |
			    HIFN_MAC_CMD_RESULT | HIFN_MAC_CMD_MODE_HASH |
			    HIFN_MAC_CMD_POS_IPSEC;
                       break;
		case CRYPTO_MD5_HMAC:
			cmd->mac_masks |= HIFN_MAC_CMD_ALG_MD5 |
			    HIFN_MAC_CMD_RESULT | HIFN_MAC_CMD_MODE_HMAC |
			    HIFN_MAC_CMD_POS_IPSEC | HIFN_MAC_CMD_TRUNC;
			break;
		case CRYPTO_SHA1:
			cmd->mac_masks |= HIFN_MAC_CMD_ALG_SHA1 |
			    HIFN_MAC_CMD_RESULT | HIFN_MAC_CMD_MODE_HASH |
			    HIFN_MAC_CMD_POS_IPSEC;
			break;
		case CRYPTO_SHA1_HMAC:
			cmd->mac_masks |= HIFN_MAC_CMD_ALG_SHA1 |
			    HIFN_MAC_CMD_RESULT | HIFN_MAC_CMD_MODE_HMAC |
			    HIFN_MAC_CMD_POS_IPSEC | HIFN_MAC_CMD_TRUNC;
			break;
		}

		if (maccrd->crd_alg == CRYPTO_SHA1_HMAC ||
		     maccrd->crd_alg == CRYPTO_MD5_HMAC) {
			cmd->mac_masks |= HIFN_MAC_CMD_NEW_KEY;
			bcopy(maccrd->crd_key, cmd->mac, maccrd->crd_klen >> 3);
			bzero(cmd->mac + (maccrd->crd_klen >> 3),
			    HIFN_MAC_KEY_LENGTH - (maccrd->crd_klen >> 3));
		}
	}

	cmd->crp = crp;
	cmd->session_num = session;
	cmd->softc = sc;

	err = hifn_crypto(sc, cmd, crp, hint);
	if (!err) {
		return 0;
	} else if (err == ERESTART) {
		/*
		 * There weren't enough resources to dispatch the request
		 * to the part.  Notify the caller so they'll requeue this
		 * request and resubmit it again soon.
		 */
#ifdef HIFN_DEBUG
		if (hifn_debug)
			device_printf(sc->sc_dev, "requeue request\n");
#endif
		kfree(cmd);
		sc->sc_needwakeup |= CRYPTO_SYMQ;
		return (err);
	}

errout:
	if (cmd != NULL)
		kfree(cmd);
	if (err == EINVAL)
		hifnstats.hst_invalid++;
	else
		hifnstats.hst_nomem++;
	crp->crp_etype = err;
	crypto_done(crp);
	return (err);
}

static void
hifn_abort(struct hifn_softc *sc)
{
	struct hifn_dma *dma = sc->sc_dma;
	struct hifn_command *cmd;
	struct cryptop *crp;
	int i, u;

	DPRINTF("%s()\n", __FUNCTION__);

	i = dma->resk; u = dma->resu;
	while (u != 0) {
		cmd = dma->hifn_commands[i];
		KASSERT(cmd != NULL, ("hifn_abort: null command slot %u", i));
		dma->hifn_commands[i] = NULL;
		crp = cmd->crp;

		if ((dma->resr[i].l & htole32(HIFN_D_VALID)) == 0) {
			/* Salvage what we can. */
			u_int8_t *macbuf;

			if (cmd->base_masks & HIFN_BASE_CMD_MAC) {
				macbuf = dma->result_bufs[i];
				macbuf += 12;
			} else
				macbuf = NULL;
			hifnstats.hst_opackets++;
			hifn_callback(sc, cmd, macbuf);
		} else {
#if 0
			if (cmd->src_map == cmd->dst_map) {
				bus_dmamap_sync(sc->sc_dmat, cmd->src_map,
				    BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE);
			} else {
				bus_dmamap_sync(sc->sc_dmat, cmd->src_map,
				    BUS_DMASYNC_POSTWRITE);
				bus_dmamap_sync(sc->sc_dmat, cmd->dst_map,
				    BUS_DMASYNC_POSTREAD);
			}
#endif

			if (cmd->src_skb != cmd->dst_skb) {
#ifdef NOTYET
				m_freem(cmd->src_m);
				crp->crp_buf = (caddr_t)cmd->dst_m;
#else
				device_printf(sc->sc_dev,
						"%s,%d: CRYPTO_F_SKBUF src != dst not implemented\n",
						__FILE__, __LINE__);
#endif
			}

			/* non-shared buffers cannot be restarted */
			if (cmd->src_map != cmd->dst_map) {
				/*
				 * XXX should be EAGAIN, delayed until
				 * after the reset.
				 */
				crp->crp_etype = ENOMEM;
				pci_unmap_buf(sc, &cmd->dst);
			} else
				crp->crp_etype = ENOMEM;

			pci_unmap_buf(sc, &cmd->src);

			kfree(cmd);
			if (crp->crp_etype != EAGAIN)
				crypto_done(crp);
		}

		if (++i == HIFN_D_RES_RSIZE)
			i = 0;
		u--;
	}
	dma->resk = i; dma->resu = u;

	hifn_reset_board(sc, 1);
	hifn_init_dma(sc);
	hifn_init_pci_registers(sc);
}

static void
hifn_callback(struct hifn_softc *sc, struct hifn_command *cmd, u_int8_t *macbuf)
{
	struct hifn_dma *dma = sc->sc_dma;
	struct cryptop *crp = cmd->crp;
	struct cryptodesc *crd;
	int i, u, ivlen;

	DPRINTF("%s()\n", __FUNCTION__);

#if 0
	if (cmd->src_map == cmd->dst_map) {
		bus_dmamap_sync(sc->sc_dmat, cmd->src_map,
		    BUS_DMASYNC_POSTWRITE | BUS_DMASYNC_POSTREAD);
	} else {
		bus_dmamap_sync(sc->sc_dmat, cmd->src_map,
		    BUS_DMASYNC_POSTWRITE);
		bus_dmamap_sync(sc->sc_dmat, cmd->dst_map,
		    BUS_DMASYNC_POSTREAD);
	}
#endif

	if (crp->crp_flags & CRYPTO_F_SKBUF) {
		if (cmd->src_skb != cmd->dst_skb) {
#ifdef NOTYET
			crp->crp_buf = (caddr_t)cmd->dst_m;
			totlen = cmd->src_mapsize;
			for (m = cmd->dst_m; m != NULL; m = m->m_next) {
				if (totlen < m->m_len) {
					m->m_len = totlen;
					totlen = 0;
				} else
					totlen -= m->m_len;
			}
			cmd->dst_m->m_pkthdr.len = cmd->src_m->m_pkthdr.len;
			m_freem(cmd->src_m);
#else
			device_printf(sc->sc_dev,
					"%s,%d: CRYPTO_F_SKBUF src != dst not implemented\n",
					__FILE__, __LINE__);
#endif
		}
	}

	if (cmd->sloplen != 0) {
		if (crp->crp_flags & CRYPTO_F_SKBUF)
			skb_copy_bits_back((struct sk_buff *)crp->crp_buf,
					cmd->src_mapsize - cmd->sloplen,
					(caddr_t)&dma->slop[cmd->slopidx], cmd->sloplen);
		else if (crp->crp_flags & CRYPTO_F_IOV)
			cuio_copyback((struct uio *)crp->crp_buf,
			    cmd->src_mapsize - cmd->sloplen,
			    cmd->sloplen, (caddr_t)&dma->slop[cmd->slopidx]);
		else
			bcopy((char *) &dma->slop[cmd->slopidx],
					cmd->src_buf + (cmd->src_mapsize - cmd->sloplen),
					cmd->sloplen);
	}

	i = dma->dstk; u = dma->dstu;
	while (u != 0) {
		if (i == HIFN_D_DST_RSIZE)
			i = 0;
#if 0
		bus_dmamap_sync(sc->sc_dmat, sc->sc_dmamap,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
#endif
		if (dma->dstr[i].l & htole32(HIFN_D_VALID)) {
#if 0
			bus_dmamap_sync(sc->sc_dmat, sc->sc_dmamap,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
#endif
			break;
		}
		i++, u--;
	}
	dma->dstk = i; dma->dstu = u;

	hifnstats.hst_obytes += cmd->dst_mapsize;

	if ((cmd->base_masks & (HIFN_BASE_CMD_CRYPT | HIFN_BASE_CMD_DECODE)) ==
	    HIFN_BASE_CMD_CRYPT) {
		for (crd = crp->crp_desc; crd; crd = crd->crd_next) {
			if (crd->crd_alg != CRYPTO_DES_CBC &&
			    crd->crd_alg != CRYPTO_3DES_CBC &&
			    crd->crd_alg != CRYPTO_AES_CBC)
				continue;
			ivlen = ((crd->crd_alg == CRYPTO_AES_CBC) ?
				HIFN_AES_IV_LENGTH : HIFN_IV_LENGTH);
			if (crp->crp_flags & CRYPTO_F_SKBUF) {
				skb_copy_bits((struct sk_buff *)crp->crp_buf,
					crd->crd_skip + crd->crd_len - ivlen,
					(caddr_t) cmd->softc->sc_sessions[cmd->session_num].hs_iv,
					ivlen);
			} else if (crp->crp_flags & CRYPTO_F_IOV) {
				cuio_copydata((struct uio *)crp->crp_buf,
				    crd->crd_skip + crd->crd_len - ivlen, ivlen,
				    cmd->softc->sc_sessions[cmd->session_num].hs_iv);
			} else {
				bcopy(cmd->src_buf + (crd->crd_skip + crd->crd_len - ivlen),
						cmd->softc->sc_sessions[cmd->session_num].hs_iv, ivlen);
			}
			break;
		}
	}

	if (macbuf != NULL) {
		for (crd = crp->crp_desc; crd; crd = crd->crd_next) {
                        int len;

                        if (crd->crd_alg == CRYPTO_MD5)
				len = 16;
                        else if (crd->crd_alg == CRYPTO_SHA1)
				len = 20;
                        else if (crd->crd_alg == CRYPTO_MD5_HMAC ||
                            crd->crd_alg == CRYPTO_SHA1_HMAC)
				len = 12;
                        else
				continue;

			if (crp->crp_flags & CRYPTO_F_SKBUF)
				skb_copy_bits_back((struct sk_buff *)crp->crp_buf,
					crd->crd_inject, macbuf, len);
			else if ((crp->crp_flags & CRYPTO_F_IOV) && crp->crp_mac)
				bcopy((caddr_t)macbuf, crp->crp_mac, len);
			break;
		}
	}

	if (cmd->src_map != cmd->dst_map)
		pci_unmap_buf(sc, &cmd->dst);
	pci_unmap_buf(sc, &cmd->src);
	kfree(cmd);
	crypto_done(crp);
}

/*
 * 7811 PB3 rev/2 parts lock-up on burst writes to Group 0
 * and Group 1 registers; avoid conditions that could create
 * burst writes by doing a read in between the writes.
 *
 * NB: The read we interpose is always to the same register;
 *     we do this because reading from an arbitrary (e.g. last)
 *     register may not always work.
 */
static void
hifn_write_reg_0(struct hifn_softc *sc, bus_size_t reg, u_int32_t val)
{
	/* device_printf(sc->sc_dev, "writing_0[%02x]=%08x\n", reg, val); */

	if (sc->sc_flags & HIFN_IS_7811) {
		if (sc->sc_bar0_lastreg == reg - 4)
			readl(sc->sc_bar0 + HIFN_0_PUCNFG);
		sc->sc_bar0_lastreg = reg;
	}
	writel(val, sc->sc_bar0 + reg);
}

static void
hifn_write_reg_1(struct hifn_softc *sc, bus_size_t reg, u_int32_t val)
{
	/* device_printf(sc->sc_dev, "writing_1[%02x]=%08x\n", reg, val); */

	if (sc->sc_flags & HIFN_IS_7811) {
		if (sc->sc_bar1_lastreg == reg - 4)
			readl(sc->sc_bar1 + HIFN_1_REVID);
		sc->sc_bar1_lastreg = reg;
	}
	writel(val, sc->sc_bar1 + reg);
}


static struct pci_device_id hifn_pci_tbl[] = {
	{ PCI_VENDOR_HIFN, PCI_PRODUCT_HIFN_7951,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, },
	{ PCI_VENDOR_HIFN, PCI_PRODUCT_HIFN_7955,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, },
	{ PCI_VENDOR_HIFN, PCI_PRODUCT_HIFN_7956,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, },
	{ PCI_VENDOR_NETSEC, PCI_PRODUCT_NETSEC_7751,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, },
	{ PCI_VENDOR_INVERTEX, PCI_PRODUCT_INVERTEX_AEON,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, },
	/*
	 * Other vendors share this PCI ID as well, such as
	 * http://www.powercrypt.com, and obviously they also
	 * use the same key.
	 */
	{ PCI_VENDOR_HIFN, PCI_PRODUCT_HIFN_7751,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, },
};
MODULE_DEVICE_TABLE(pci, hifn_pci_tbl);


/*
 * PUBLIC KEY OPERATIONS/SUPPORT
 *
 */
static void
hifn_rng_init(struct hifn_softc *sc)
{
	if (sc->sc_flags & HIFN_HAS_RNG) {
		u_int32_t r;
		if (sc->sc_flags & HIFN_IS_7811) {
			r = READ_REG_1(sc, HIFN_1_7811_RNGENA);
			if (r & HIFN_7811_RNGENA_ENA) {
				r &= ~HIFN_7811_RNGENA_ENA;
				WRITE_REG_1(sc, HIFN_1_7811_RNGENA, r);
			}
			WRITE_REG_1(sc, HIFN_1_7811_RNGCFG,
				    HIFN_7811_RNGCFG_DEFL);
			r |= HIFN_7811_RNGENA_ENA;
			WRITE_REG_1(sc, HIFN_1_7811_RNGENA, r);
		} else
			WRITE_REG_1(sc, HIFN_1_RNG_CONFIG,
				    READ_REG_1(sc, HIFN_1_RNG_CONFIG) |
				    HIFN_RNGCFG_ENA);
		
		sc->sc_rngfirst = 1;
	}
}

#if !defined(CONFIG_OCF_HIFN_PKMMAP)
static void
hifn_pk_init(struct hifn_softc *sc)
{
	WRITE_REG_1(sc, HIFN_1_PUB_MODE, HIFN_PKMODE_ENHANCED);
	device_printf(sc->sc_dev, "mode=%08x\n", READ_REG_1(sc,HIFN_1_PUB_MODE));
	WRITE_REG_1(sc, HIFN_1_PUB_IEN, HIFN_PUBIEN_DONE);

	/* reset any bits which are set */
	WRITE_REG_1(sc, HIFN_1_PUB_STATUS, READ_REG_1(sc, HIFN_1_PUB_STATUS));
	
	memset(sc->sc_bar1+HIFN_1_PUB_MEM, 0, HIFN_1_PUB_MEMSIZE);
}
#endif

static int
hifn_pk_reset(struct hifn_softc *sc)
{
	int i;

	DPRINTF("%s()\n", __FUNCTION__);

	/* Reset 7951 public key/rng engine */
	WRITE_REG_1(sc, HIFN_1_PUB_RESET,
		    READ_REG_1(sc, HIFN_1_PUB_RESET) | HIFN_PUBRST_RESET);
	
	for (i = 0; i < 100; i++) {
		DELAY(1000);
		if ((READ_REG_1(sc, HIFN_1_PUB_RESET) &
		     HIFN_PUBRST_RESET) == 0)
			break;
	}
	
	if (i == 100) {
		device_printf(sc->sc_dev, "public key reset failed\n");
		return (1);
	}
	
#if !defined(CONFIG_OCF_HIFN_PKMMAP)
	hifn_pk_init(sc);
#endif

	/* after a reset, the rng engine will need to be re-enabled */
	hifn_rng_init(sc);
	
	return 0;
}

/*
 * hifn_init_pkrng - set up the 785x public key and RNG unit.
 *  
 * @sc - the software context for the unit in question.
 *
 * these functions are generally done only once. Use reset_pk(),
 * or pk_init and rng_init.
 *
 */
static int
hifn_init_pkrng(struct hifn_softc *sc)
{
	int i;

	DPRINTF("%s()\n", __FUNCTION__);

	if (sc->sc_flags & HIFN_HAS_PUBLIC) {
		i = hifn_pk_reset(sc);
		if(i) return i;
	}

#ifdef CONFIG_OCF_RANDOMHARVEST
	/* hook-up the rng, if available */
	if (sc->sc_flags & HIFN_HAS_RNG) {
		crypto_rregister(sc->sc_cid, hifn_read_random, sc);
	}
#endif

	/* Enable public key engine, if available */
	if (sc->sc_flags & HIFN_HAS_PUBLIC) {
		WRITE_REG_1(sc, HIFN_1_PUB_IEN, HIFN_PUBIEN_DONE);
		sc->sc_dmaier |= HIFN_DMAIER_PUBDONE;
		WRITE_REG_1(sc, HIFN_1_DMA_IER, sc->sc_dmaier);

		DPRINTF("PUBLIC %s()\n", __FUNCTION__);

#if defined(CONFIG_OCF_HIFN_PKMMAP)
		sc->sc_miscdev = hifnpk_miscdev;
		{
			int retval = misc_register(&sc->sc_miscdev);
			if(retval) return retval;
		}

		device_printf(sc->sc_dev, "assigned to misc device %u\n", sc->sc_miscdev.minor);
#else
		device_printf(sc->sc_dev, "registered to OCF\n");
		
		INIT_LIST_HEAD(&sc->sc_pk_q);
		spin_lock_init(&sc->sc_pk_lock);
		sc->sc_pk_qcur = NULL;

		crypto_kregister(sc->sc_cid, CRK_MOD_EXP, 0,
				 hifn_vulcan_kprocess, sc);
		crypto_kregister(sc->sc_cid, CRK_ADD, 0,
				 hifn_vulcan_kprocess, sc);

		init_timer(&sc->sc_pk_timer);
		sc->sc_pk_timer.expires = jiffies + HZ; /* /10;*/ /* 1/10 second */
		sc->sc_pk_timer.data = sc->sc_num;
		sc->sc_pk_timer.function = hifn_pk_timeout;	/* timer handler */
		add_timer(&sc->sc_pk_timer);
#endif		

	}

	DPRINTF("%s() END\n", __FUNCTION__);

	return (0);
}

void hifn_pk_print_status(struct hifn_softc *sc, char *str, u_int32_t stat)
{
	device_printf(sc->sc_dev, "%s status: %08x ", str, stat);
	if(stat & HIFN_PUBSTS_DONE) {
		printf("done ");
	}
	if(stat & HIFN_PUBSTS_CARRY) {
		printf("carry ");
	}
	if(stat & 0x4) {
		printf("sign(2) ");
	}
	if(stat & 0x8) {
		printf("zero(3) ");
	}
	if(stat & HIFN_PUBSTS_FIFO_EMPTY) {
		printf("empty ");
	}
	if(stat & HIFN_PUBSTS_FIFO_FULL) {
		printf("full ");
	}
	if(stat & HIFN_PUBSTS_FIFO_OVFL) {
		printf("overflow ");
	}
	if(stat & HIFN_PUBSTS_FIFO_WRITE) {
		printf("write=%d ", (stat & HIFN_PUBSTS_FIFO_WRITE)>>16);
	}
	if(stat & HIFN_PUBSTS_FIFO_READ) {
		printf("read=%d ", (stat & HIFN_PUBSTS_FIFO_READ)>>24);
	}
	printf("\n");
}

#if defined(CONFIG_OCF_HIFN_PKMMAP)
static int hifn_vulcanpk_open(struct inode * inode, struct file * filp)
{
	struct hifn_softc *sc = hifn_chip_idx[0];

	if(iminor(inode) == sc->sc_miscdev.minor) {
		filp->private_data = (void *)sc;
	} else {
		printk("unknown hifn minor device: %d\n", iminor(inode));
	}
	return 0;
}

/* support mapping the PK engine's registers into a userspace application */
static int hifn_vulcanpk_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct hifn_softc *sc;
	unsigned long addr;

	/* can not map other than the first, and at multiples of the
	 * the page size.
	 */
	if (((vma->vm_end - vma->vm_start) != PAGE_SIZE) || vma->vm_pgoff)
		return -EINVAL;

	sc = file->private_data;
	addr = sc->sc_bar1phy;

	if (addr & (PAGE_SIZE - 1))
		return -ENOSYS;

	vma->vm_flags |= VM_IO;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (io_remap_pfn_range(vma, vma->vm_start, addr >> PAGE_SHIFT,
					PAGE_SIZE, vma->vm_page_prot)) {
		printk(KERN_ERR "%s: io_remap_pfn_range failed\n",
			__FUNCTION__);
		return -EAGAIN;
	}

	return 0;
}

/* these are private IOCTLs to the vulcan PK engine */
static int hifn_vulcanpk_ioctl(struct inode *inode, struct file *file,
			       unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case 1:
		/* do something */
		return 0;

	default:
		return -EIO;
	}
}

static struct file_operations hifnpk_chrdev_ops = {
	.owner		= THIS_MODULE,
	.open		= hifn_vulcanpk_open,
	.ioctl		= hifn_vulcanpk_ioctl,
	.mmap		= hifn_vulcanpk_mmap,
};


static struct miscdevice hifnpk_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vulcanpk",
	.fops = &hifnpk_chrdev_ops,
};

#else

/*
 * process PK operations from userland
 *
 */
static int
hifn_vulcan_kprocess(void *arg, struct cryptkop *krp, int hint)
{
	struct hifn_softc *sc = arg;
	struct hifn_pkq *q;
	unsigned long flags;

	DPRINTF("%s()\n", __FUNCTION__);
	if(hifn_debug) device_printf(sc->sc_dev, "starting processing on krp=%p\n", krp);

	if (sc == NULL) {
		krp->krp_status = EINVAL;
		goto err;
	}

	switch(krp->krp_op) {
	case CRK_MOD_EXP:
	case CRK_ADD:
		break;

	default:
		krp->krp_status = EOPNOTSUPP;
		goto err;
	}

	q = (struct hifn_pkq *) kmalloc(sizeof(*q), GFP_KERNEL);
	if (q == NULL) {
		krp->krp_status = ENOMEM;
		goto err;
	}
	memset(q, 0, sizeof(*q));
	q->pkq_krp = krp;
	INIT_LIST_HEAD(&q->pkq_list);

	spin_lock_irqsave(&sc->sc_pk_lock, flags);
	list_add_tail(&q->pkq_list, &sc->sc_pk_q);
	hifn_kfeed(sc);
	spin_unlock_irqrestore(&sc->sc_pk_lock, flags);
	return (0);

err:
	crypto_kdone(krp);
	return (0);
}

/*
 * param is in little endian byte string, which is great, because
 * the vulcan PK engine expects things in little endian format.
 */
static void hifn_copyPkValueTo(struct hifn_softc *sc,
			       struct crparam *param,
			       unsigned int chunkSize,
			       int pkRegNum)
{
	int wordcnt = (3+(param->crp_nbits+7)/8)/4;
	u_int32_t *words = (u_int32_t *)param->crp_p;
	int regNum = (pkRegNum * chunkSize) + HIFN_1_PUB_MEM;

	if(hifn_debug) device_printf(sc->sc_dev, "copying %d words (%d bits) to %02x from %p\n",
				     wordcnt,
				     param->crp_nbits, 
				     (regNum - HIFN_1_PUB_MEM),
				     words);
	while(wordcnt-->0) {
		writel(*words++, sc->sc_bar1 + regNum);
		regNum += 4;
	}

	//hexdump(sc->sc_bar1, (pkRegNum * chunkSize) + HIFN_1_PUB_MEM,
	//	(param->crp_nbits+7)/8);
}

/*
 * 
 */
static void hifn_clearPkReg(struct hifn_softc *sc,
			    unsigned int chunkSize,
			    int pkRegNum)
{
	int regNum = (pkRegNum * chunkSize) + HIFN_1_PUB_MEM;

	memset(sc->sc_bar1 + regNum, 0, chunkSize);
}

static void hifn_copyPkValueFrom(struct hifn_softc *sc,
				 struct crparam *param,
				 unsigned int chunkSize,
				 unsigned int pkRegNum)
{
	int wordcnt = (3+(param->crp_nbits+7)/8)/4;
	u_int32_t *words = (u_int32_t *)param->crp_p;
	int regNum = (pkRegNum * chunkSize) + HIFN_1_PUB_MEM;

	if(hifn_debug) device_printf(sc->sc_dev, "copying %d words (%d bits) from %02x to %p\n",
				     wordcnt,
				     param->crp_nbits, 
				     (regNum - HIFN_1_PUB_MEM),
				     words);
	while(wordcnt-->0) {
		*words++ = READ_REG_1(sc, regNum);
		regNum += 4;
	}
}

static inline
void hifn_write_pkop(struct hifn_softc *sc,
		     unsigned int pk_op,
		     unsigned int chunkSize,
		     unsigned int aRegister,
		     unsigned int bRegister,
		     unsigned int mRegister,
		     unsigned int explen,
		     unsigned int redlen)
{
	u_int32_t oplen, op;
	int aOffset, bOffset, mOffset;
	unsigned int modLen;


	aOffset = aRegister * (chunkSize / 64);
	bOffset = bRegister * (chunkSize / 64);
	mOffset = mRegister * (chunkSize / 64);
	modLen = (chunkSize * 8) / 32;

	oplen = (modLen << HIFN_PUBOPeLEN_MOD_SHIFT)|
		(explen << HIFN_PUBOPeLEN_EXP_SHIFT)|
		(redlen << HIFN_PUBOPeLEN_RED_SHIFT);
	op = (pk_op << HIFN_PUBOPe_OP_SHIFT)|
		(aOffset << HIFN_PUBOPe_ASHIFT)|
		(bOffset << HIFN_PUBOPe_BSHIFT)|
		(mOffset << HIFN_PUBOPe_MSHIFT);

	if (hifn_debug) {
		device_printf(sc->sc_dev, "pk_op(%08x, %08x)\n", oplen, op);
		hifn_pk_print_status(sc, "pk_op before", READ_REG_1(sc, HIFN_1_PUB_STATUS));
	}
	WRITE_REG_1(sc, HIFN_1_PUB_FIFO_OPLEN, oplen);
	WRITE_REG_1(sc, HIFN_1_PUB_FIFO_OP, op);

	if (hifn_debug) hifn_pk_print_status(sc, "pk_op after",
					    READ_REG_1(sc, HIFN_1_PUB_STATUS));
}

/*
 * hifn_calc_bitlen - determine how many significant bits there are.
 *
 * @secval - pointer to array of bytes, little-endian format.
 * @seclen - number of bytes of data.
 *
 * This function calculates where the most-significant 1 bit in a little
 * endian value stored at secval.
 *
 */
 
static int hifn_calc_bitlen(unsigned char *secval,
			    unsigned int seclen)
{
	int explen;
			
	explen = seclen * 8;
	secval += (seclen-1);
	while(*secval == 0 && seclen > 0) {
		secval--;
		seclen--;
		explen-=8;
	}

	printk("seclen=%d *secval=%02x\n", seclen, *secval);
	
	/* fix up final byte size */
	if((*secval & 0x80) == 0) {
		explen--;
		
		if((*secval & 0x40) == 0) {
			explen--;
			
			if((*secval & 0x20) == 0) {
				explen--;
				
				if((*secval & 0x10) == 0) {
					explen--;
					
					if((*secval & 0x08) == 0) {
						explen--;
						
						if((*secval & 0x04) == 0) {
							explen--;
							
							if((*secval & 0x02) == 0) {
								explen--;
								
								if((*secval & 0x01) == 0) {
									explen--;
								}
							}
						}
					}
				}
			}
		}
	}

	printk("explen=%d\n", explen);
	return explen;
}
    
static int
hifn_vulcan_kstart(struct hifn_softc *sc)
{
	struct cryptkop *krp = sc->sc_pk_qcur->pkq_krp;
	int mod_bits;
	int chunkSize;  /* in bytes */
	int modlen, explen;     /* in bits */
	struct crparam *rec;

	DPRINTF("%s()\n", __FUNCTION__);


	switch(krp->krp_op) {
	case CRK_MOD_EXP:
		if (krp->krp_iparams < 3 || krp->krp_oparams != 1) {
			krp->krp_status = EINVAL;
			return (1);
		}
		if(krp->krp_iparams != 4) {
			/* we would have to calculate the reciprocal!!!!
			 * which we don't know how to do yet, so make it
			 * invalid for now.
			 */
			krp->krp_status = EINVAL;
			return (1);
		} else {
			rec = &krp->krp_param[CRK_MOD_PARAM_RECIP];
		}

		/* need to find exponent length, in bits */
		explen = hifn_calc_bitlen(krp->krp_param[CRK_MOD_PARAM_EXP].crp_p,
					  krp->krp_param[CRK_MOD_PARAM_EXP].crp_nbits/8);
		mod_bits = krp->krp_param[CRK_MOD_PARAM_MOD].crp_nbits;
		modlen = mod_bits / 4;
		chunkSize = mod_bits / 8;

		sc->sc_pk_qcur->pkq_chunksize  = chunkSize;
		sc->sc_pk_qcur->pkq_oparam_reg = 2;

		/*
		 * param 0 is base, goes into register A(0)
		 * param 1 is exponent, goes into register B(1).
		 * register 2 will be the result, zero it.
		 * register 3 used as scratch, zero it.
		 * param 2 is the modulus, goes into register M(4)
		 * param 3 is the reciprocal, goes into register M(5)
		 * M(6) and M(7) are also scratch and have to be zero'ed.
		 */
		hifn_copyPkValueTo(sc, &krp->krp_param[CRK_MOD_PARAM_BASE],chunkSize,0);
		hifn_copyPkValueTo(sc, &krp->krp_param[CRK_MOD_PARAM_EXP], chunkSize,1);
		hifn_clearPkReg(sc, chunkSize, sc->sc_pk_qcur->pkq_oparam_reg);
		hifn_clearPkReg(sc, chunkSize, 3);
		hifn_copyPkValueTo(sc, &krp->krp_param[CRK_MOD_PARAM_MOD], chunkSize,4);
		hifn_copyPkValueTo(sc, rec, chunkSize,5);
		hifn_clearPkReg(sc, chunkSize, 6);
		hifn_clearPkReg(sc, chunkSize, 7);
		

#ifdef HEXDUMP
		if(hifn_debug) {
			hexdump(sc->sc_bar1, HIFN_1_PUB_MEM, HIFN_1_PUB_MEMSIZE);
		}
#endif

		hifn_write_pkop(sc, HIFN_PUBOPe_OP_MODEXP,
				chunkSize,  /* chunk size in bytes */
				0, /* A argument */
				1, /* B argument */
				4, /* M argument */
				explen-1,  /* explen */
				0  /* reducent length */);
		break;
		
	case CRK_ADD:
#define	HIFN_CRK_PARAM_A	0
#define	HIFN_CRK_PARAM_B	1
		if(krp->krp_iparams != 2 ||
		   krp->krp_oparams != 1) {
			krp->krp_status = EINVAL;
			return (1);
		}
		chunkSize = 384;
		sc->sc_pk_qcur->pkq_chunksize  = chunkSize;
		sc->sc_pk_qcur->pkq_oparam_reg = 2;

		/* param 1 is A, param 2 is B,
		 * and result will be in B(1)
		 */
		hifn_copyPkValueTo(sc, &krp->krp_param[HIFN_CRK_PARAM_A],chunkSize,0);
		hifn_copyPkValueTo(sc, &krp->krp_param[HIFN_CRK_PARAM_B],chunkSize,1);
		hifn_clearPkReg(sc, chunkSize, sc->sc_pk_qcur->pkq_oparam_reg);

#ifdef HEXDUMP
		if(hifn_debug) {
			hexdump(sc->sc_bar1, HIFN_1_PUB_MEM, HIFN_1_PUB_MEMSIZE);
		}
#endif

		hifn_write_pkop(sc, HIFN_PUBOPe_OP_ADD,
				chunkSize,  /* chunk size in bytes */
				0, /* A argument */
				1, /* B argument */
				4, /* M argument */
				0,  /* explen */
				0   /* reducent length */);
		break;

	default:
		/* unknown_op: */
		device_printf(sc->sc_dev, "receive kop=%d\n", krp->krp_op);
		krp->krp_status = ENOSYS;
		return (1);
	}

	/* defer timer for 1 second */
	mod_timer(&sc->sc_pk_timer, jiffies + HZ);

	return (0);

#if 0
too_big:
#endif
	krp->krp_status = E2BIG;
	return (1);

#if 0
too_small:
	krp->krp_status = ERANGE;
	return (1);
bad_domain:
	krp->krp_status = EDOM;
	return (1);
#endif
}

static void
hifn_kfeed(struct hifn_softc *sc)
{
	struct hifn_pkq *q, *tmp;

	DPRINTF("%s()\n", __FUNCTION__);

	if (list_empty(&sc->sc_pk_q) && sc->sc_pk_qcur == NULL) {
		DPRINTF("nothing for device to do\n");
		del_timer(&sc->sc_pk_timer);
		return;
	}
	if (sc->sc_pk_qcur != NULL) {
		DPRINTF("device is still busy\n");
		return;
	}
	list_for_each_entry_safe(q, tmp, &sc->sc_pk_q, pkq_list) {
		sc->sc_pk_qcur = q;
		list_del(&q->pkq_list);
		if (hifn_vulcan_kstart(sc) != 0) {
			crypto_kdone(q->pkq_krp);
			kfree(q);
			sc->sc_pk_qcur = NULL;
		}
		/*
		 * must have suceeded, interrupt will be issued
		 * when the PK operatin is done, and we will
		 * complete the PK operation.
		 */
	}
}

/*
 * hifn_kintr - handle interrupts related to PK engine.
 *
 * @sc: the specific chip software context.
 *
 * deal with any interrupts from the PK engine. We are not called unless
 * the PUB_DONE bit was set, so we may assume that it was set.
 *
 * Note, this routine is called from hifn_intr(), so we assume that all
 * locks are already taken.
 */
void hifn_kintr(struct hifn_softc *sc)
{
	struct hifn_pkq *q;
	struct cryptkop *krp;
	int oparam;
	int stat = READ_REG_1(sc, HIFN_1_PUB_STATUS);

	DPRINTF("%s()\n", __FUNCTION__);
	if(hifn_debug) {
		hifn_pk_print_status(sc, "kintr", stat);
	}

	q = sc->sc_pk_qcur;
	if(q == NULL) {
		DPRINTF("%s() spurious interrupt\n", __FUNCTION__);
		sc->sc_pk_spurious++;
		return;
	}
		
	sc->sc_pk_qcur = NULL;
	
	krp = q->pkq_krp;
	
	oparam = krp->krp_iparams;
	hifn_copyPkValueFrom(sc,
			     &krp->krp_param[oparam],
			     q->pkq_chunksize,
			     q->pkq_oparam_reg);
	
#ifdef HEXDUMP
	if(hifn_debug) {
		hexdump(sc->sc_bar1, HIFN_1_PUB_MEM, HIFN_1_PUB_MEMSIZE);
	}
#endif

	/* waste as little time as possible feeding another operation
	 * into the Public key engine
	 */
	hifn_kfeed(sc);
	
	crypto_kdone(q->pkq_krp);
	kfree(q);
}

/*
 * hifn_pk_timeout - check once a second to see if PK engine got stuck.
 * 
 * @arg: hifn vulcan instance number
 *
 * The PK engine can get stuck if it is given a bad reciprocal for the moduli,
 * as it will never be able to do the modulus operation properly. Yes, a userspace
 * process could certain do a DOS on the the chip, since we'd only reset it
 * once a second. Perhaps, we should keep track of the PID of the offending
 * processing, and refuse them in the future.
 *
 * Note that the interrupt routine will put this timer off
 *
 *
 */
static void hifn_pk_timeout(unsigned long arg)
{
	struct hifn_pkq *q;
	struct hifn_softc *sc;
	unsigned long l_flags;

	DPRINTF("%s(%lu)\n", __FUNCTION__, arg);

	if (arg >= HIFN_MAX_CHIPS)
		return;
	sc = hifn_chip_idx[arg];
	if (!sc)
		return;

	HIFN_LOCK(sc);
	q = sc->sc_pk_qcur;

	hifn_pk_print_status(sc, "pk_timeout ", READ_REG_1(sc, HIFN_1_PUB_STATUS));
	sc->sc_pk_qcur = NULL;
	if(q == NULL) {
		/* nothing happening, so it's fine, let the timer go */
		goto done;
	}

	/*
	 * something active, so it must have gotten stuck, kill current
	 * operation, reset PK engine, and start a new operation.
	 */
	if(q->pkq_krp) {
		/* it should never be NULL, but let's be careful */
		q->pkq_krp->krp_status = EDOM;
		crypto_kdone(q->pkq_krp);
	}
	kfree(q);


	/* reset engine */
	device_printf(sc->sc_dev, "PK engine stuck --- resetting\n");
	hifn_pk_reset(sc);

	/* feed a new entry, if any to the engine */
	hifn_kfeed(sc);

done:
	HIFN_UNLOCK(sc);

}
#endif /* PKMMAP */


static struct pci_driver hifn_driver = {
	.name         = "hifn",
	.id_table     = hifn_pci_tbl,
	.probe        =	hifn_probe,
	.remove       = hifn_remove,
	/* add PM stuff here one day */
};

static int __init hifn_init (void)
{
	DPRINTF("%s(%p)\n", __FUNCTION__, hifn_init);
	return pci_module_init(&hifn_driver);
}

static void __exit hifn_exit (void)
{
	pci_unregister_driver(&hifn_driver);
}

module_init(hifn_init);
module_exit(hifn_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("David McCullough <dmccullough@cyberguard.com>");
MODULE_DESCRIPTION("OCF driver for hifn PCI crypto devices");
