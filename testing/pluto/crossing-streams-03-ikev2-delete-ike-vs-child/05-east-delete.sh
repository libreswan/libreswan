# initiate delete; WEST will block the message leaving EAST hanging

ipsec whack --delete-ike --name east-west --asynchronous

# now back to WEST
