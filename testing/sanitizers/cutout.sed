# simple standalone lines
/==== cut ====/,/==== tuc ====/d

# post mortem
/>>>>>>>>> post-mortem >>>>>>>>>>/,/<<<<<<<<<< post-mortem <<<<<<<<<</ d

# embedded and repeated within a line
s/>>>>>>>>>>cut>>>>>>>>>> [^ ]* <<<<<<<<<<tuc<<<<<<<<<<//g
s/>>>>>>>>>>cutnonzeroexit>>>>>>>>>>.*<<<<<<<<<<tuc<<<<<<<<<<//g

