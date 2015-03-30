__author__ = 'ilias'

import os
import glob

directoryContainingFiles = "\\FILESERVER01\\DIRECTORY"

def analyse():
    os.chdir(directoryContainingFiles)
    for file in glob.glob("*.exe"):
        print "Scanning: " + file
        os.system('python vt.py ' + '"' + directoryContainingFiles + file + '"')

if __name__ == '__main__':
    analyse()
