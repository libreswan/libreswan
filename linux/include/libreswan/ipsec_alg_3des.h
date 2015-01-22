struct TripleDES_context {
	des_key_schedule s1;
	des_key_schedule s2;
	des_key_schedule s3;
};
typedef struct TripleDES_context TripleDES_context;

#define ESP_3DES_KEY_SZ         (3 * sizeof(des_cblock))
#define ESP_3DES_CBC_BLK_LEN    8

