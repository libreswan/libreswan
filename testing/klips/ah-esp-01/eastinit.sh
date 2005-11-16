ipsec setup start

/testing/pluto/bin/wait-until-policy-loaded

# this should get added to the conn, ultimately
ipsec whack --label "\"SAwest-east\" leftrsasigkey"  --keyid "@west" --pubkeyrsa "0sAQNzGEFs18VKT00sA+4p+GUKn9C55PYuPQca6C+9Qhj0jfMdQnTRTDLeI+lp9TnidHH7fVpq+PkfiF2LHlZtDwMurLlwzbNOghlEYKfQ080WlOTTUAmOLhAzH28MF70q3hzq0m5fCaVZWtxcV+LfHWdxceCkjBUSaTFtR2W12urFCBz+SB3+OM33aeIbfHxmck2yzhJ8xyMods5kF3ek/RZlFvgN8VqBdcFVrZwTh0mXDCGN12HNFixL6FzQ1jQKerKBbjb0m/IPqugvpVPWVIUajUpLMEmi1FAXc1mFZE9x1SFuSr0NzYIu2ZaHfvsAZY5oN+I+R2oC67fUCjgxY+t7"
ipsec whack --label "\"SAwest-east\" rightrsasigkey"  --keyid "@east" --pubkeyrsa "0sAQN3cn11FrBVbZhWGwRnFDAf8O9FHBmBIyIvmvt0kfkI2UGDDq8k+vYgRkwBZDviLd1p3SkL30LzuV0rqG3vBriqaAUUGoCQ0UMgsuX+k01bROLsqGB1QNXYvYiPLsnoDhKd2Gx9MUMHEjwwEZeyskMT5k91jvoAZvdEkg+9h7urbJ+kRQ4e+IHkMUrreDGwGVptV/hYQVCD54RZep6xp5ymaKRCDgMpzWvlzO80fP7JDjSZf9LI/MMu6c+qwXIKnWoNha75IhFyLWniVczxK2RdhmMhLsi0kC0CoOwWDSIEOb+5zbECDjjud+SF5tT8qRCWnSomX8jtbCdZ50WraQlL"
ipsec whack --name SAwest-east --encrypt --tunnel --pfs --authenticate --rsasig --host "192.1.2.23"  --nexthop "192.1.2.45" --updown "ipsec _updown" --id "@east" --to --host "192.1.2.45" --nexthop "%direct" --updown "ipsec _updown" --id "@west" --ipseclifetime "28800" --rekeymargin "540" --keyingtries "1"
echo end eastinit.sh
