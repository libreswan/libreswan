; example.com zone for FreeS/WAN testing
; This file belongs in /var/named/test.zone

; add to /etc/named.conf:

;;;// forward for FreeS/WAN testing:
;;;zone "example.com" {
;;;	type master;
;;;	file "test.zone";
;;;};

$TTL 8h
$ORIGIN example.com.

@	3D IN SOA	localhost. root.localhost. (
					; serial
					; YYYYMMDDnn
					  2015030301
					12H		; refresh
					30M		; retry
					5w6d16h		; expiry
					3D )		; minimum

	IN NS	localhost.

west	IN A	127.95.7.1
	IN KEY 0x4200 4 1 AQOFtqrs57eghHmYREoCu1iGn4kXd+a6yT7wCFUk54d9i08mR4h5uFKPhc9fq78XNqz1AhrBH3SRcWAfJ8DaeGvZ0ZvCrTQZn+RJzX1FQ4fjuGBO0eup2XUMsYDw01PFzQ9O4qlwly6niOcMTxvbWgGcl+3DYfRvHgxet8kNtfqzHQ==
	IN TXT	"X-IPsec-Server(10)=@west.example.com AQOFtqrs57eghHmYREoCu1iGn4kXd+a6yT7wCFUk54d9i08mR4h5uFKPhc9fq78XNqz1AhrBH3SRcWAfJ8DaeGvZ0ZvCrTQZn+RJzX1FQ4fjuGBO0eup2XUMsYDw01PFzQ9O4qlwly6niOcMTxvbWgGcl+3DYfRvHgxet8kNtfqzHQ=="

east	IN A	127.95.7.2
	IN KEY 0x4200 4 1 AQNWmttqbM8nIypsHEULynOagFyV1MQ+/1yF5sa32abxBb2fimah7NsHM9l/KpNo7RGtiP0L6triedsZ0xz1Maa4DPnZlrtexu5uIH+FH34SUr7Xe2RcHnLVOznHMzacgcjrOUvV/nA9OEGvm7vRsMAWm/VjNuNugogFreiYEpFMQQ==
	IN TXT	"X-IPsec-Server(10)=@east.example.com AQNWmttqbM8nIypsHEULynOagFyV1MQ+/1yF5sa32abxBb2fimah7NsHM9l/KpNo7RGtiP0L6triedsZ0xz1Maa4DPnZlrtexu5uIH+FH34SUr7Xe2RcHnLVOznHMzacgcjrOUvV/nA9OEGvm7vRsMAWm/VjNuNugogFreiYEpFMQQ=="

north	IN A	127.95.7.3
	IN KEY 0x4200 4 1 AQN4JFU9gRnG336z1n1cV2LA6ACi1TjXfv3pvl6DRqa6uqBFM9RO4oArPc6FsBkBwEmMr8cpeFn4mVaepVe63qnvmQbGXVcRwhx0a509M824HjnyM04Xpoh2UuP/Mhnkm1cynunRuyGqXaZhlj4s+GbcOxPXhopz94wer+Qs/qvGqw==
	IN TXT	"X-IPsec-Server(10)=@north.example.com AQN4JFU9gRnG336z1n1cV2LA6ACi1TjXfv3pvl6DRqa6uqBFM9RO4oArPc6FsBkBwEmMr8cpeFn4mVaepVe63qnvmQbGXVcRwhx0a509M824HjnyM04Xpoh2UuP/Mhnkm1cynunRuyGqXaZhlj4s+GbcOxPXhopz94wer+Qs/qvGqw=="

south	IN A	127.95.7.4
	IN KEY 0x4200 4 1 AQOKe6+kbDtp4PB8NZshjCBw8z5wuGCAddokgSDATW47tNmQhUvzlnT1ia1ZsyiRFph1LJkz+A0bkbOhPr1vWUJHK6/s+Y8Rf7GSZC0Fi5Fr4DgpWwswzFaLl4baRfeu8z4k147dtSoG4K/6UfQ+IbqML5lwm92uRqONszbn/PDDPQ==
	IN TXT	"X-IPsec-Server(10)=@south.example.com AQOKe6+kbDtp4PB8NZshjCBw8z5wuGCAddokgSDATW47tNmQhUvzlnT1ia1ZsyiRFph1LJkz+A0bkbOhPr1vWUJHK6/s+Y8Rf7GSZC0Fi5Fr4DgpWwswzFaLl4baRfeu8z4k147dtSoG4K/6UfQ+IbqML5lwm92uRqONszbn/PDDPQ=="

; RSA 4096 bits   k4096.example.com   Thu Oct 30 11:42:52 2003
k4096	IN	TXT	"X-IPsec-Server(10)=@k4096.example.com" " AQN7Ces6bI9ZItDv+UpfC0n110D2+ENeoBv3yV16d7hJNs7h3oJHUhjdzcSLOdkpP3lI+vazx7XiEFPjVV3R9y+nc7DCIpQoLlTvuZwUyIVglN1QTQzgcFAYjNjjY6VK6aCijyXS/S091u3YeTwQP3CZM/9i+ZLdcP9Bwv1E4l1axzDsEm/rtStsA7ktUS3LkoeNv+6/YFoP02kxiPkkKajiGsRC7D7VReKjLmY9yZ+xxgrmaUTHgWv2tQnAig" "hMkUv0DNI/8uZ/CeLwU1X3bewiSdDFIQ0HCKhoFmkeC4/eUb+GWsI/hIw0NsTukGZQccutg1Xx8ks4aAPjSUQTm/9JSDuU0ksmj6MpvYqQ3LR4D+b6FJJCBXffKvv9bPHo+srBWzjs0JABtAj0fVj0KWssboONx076HTmOGp6LPMWGDipm1/FY4vXMuYU3QDCwBYWFZNybMaHqpp8mOGMqva9u18ZGZEKzp4C1XWRoApnfK/rhpoMQWLQG7G3bM" "CsqqlmTeLHS7Vurl3bL8+0kHgyMXHoMmnNJngmJNbnvH/LMtkidVTuoUngTuFHjwr0CAE9n0wkkywfVD3R298yTRpPPotVQpHZWC7nAgfQq28xNY2BwufwXCCnIRBn9SYRR0hXOFyvKRMyguCEI18UqfTFnADxeR/3gQOJVOF/eBDwM1Q=="

victoria	IN A	127.95.7.10
vancouver	IN A	127.95.7.11
truro		IN A	127.95.7.21
antigonish	IN A	127.95.7.22
