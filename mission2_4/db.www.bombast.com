;
; BIND data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.www.bombast.com. admin.www.bombast.com. (
			      3		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
; name  servers - NS records
        IN      NS      ns1.www.bombast.com.
        IN      NS      ns2.www.bombast.com.

; name servers - A records
ns1.www.bombast.com.   IN      A       192.168.1.4
ns2.www.bombast.com.   IN      A       192.168.1.5

; 10.4.7.0/24 - A records
www.bombast.com. IN      A       10.4.7.1
