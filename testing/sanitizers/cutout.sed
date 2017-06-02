# simple standalone lines
/==== cut ====/,/==== tuc ====/d
# embedded but at the end of a line, see runner.py
s/>>>>>>>>>>cut>>>>>>>>>> [^ ]* <<<<<<<<<<tuc<<<<<<<<<<//
