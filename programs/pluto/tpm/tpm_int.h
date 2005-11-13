extern Tcl_Interp *PlutoInterp;

struct packet_byte_stream;

extern Tcl_Obj *tpm_StateToInstanceObj(struct state *st);
extern Tcl_Obj *tpm_ConnectionToInstanceObj(struct connection *st);
extern Tcl_Obj *tpm_MessageDigestToInstanceObj(struct msg_digest *st);
extern Tcl_Obj *tpm_BufToCharPointer(u_int8_t *ptr);
extern Tcl_Obj *tpm_IsakmpHdrToInstanceObj(struct isakmp_hdr *hdr);
extern Tcl_Obj *tpm_PbStreamToInstanceObj(struct packet_byte_stream *pbs);
extern Tcl_Obj *tpm_IntPToInstanceObj(int *ip);
extern void pbs_bytes(struct packet_byte_stream *pbs, char *out, int *max);
extern void tpm_initCallbacks(Tcl_Interp *PlutoInterp);



