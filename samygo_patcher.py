#!/usr/bin/env python

#    SamyGo Samsung TV Firmware Telnet Enable Patcher
#    Copyright (C) 2009  Erdem U. Altunyurt

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    SamyGo Home Page: http://samygo.sourceforge.net

#version = 0.01 #initial Release
version = 0.02	#Added & after telnet init for run exeDSP if telnet script returns error or not.

import os
import sys
import binascii

def xor(fileTarget, key):
 
	ifile = fileTarget
	ofile = fileTarget+".xor"
 
	if os.path.isfile(key):
		kf = open(key)
		keyData = kf.read()
		kf.close()
	else:
		keyData = key
 
	e = open(ofile, "w")
	f = open(ifile, "r")
 
	FileSize = bytesToCopy = os.stat( fileTarget )[6]
	percent_show = 0
 
	while bytesToCopy:
 
		if bytesToCopy >= len(keyData):
			data = f.read(len(keyData))
			bytesToCopy -= len(keyData)
			encryptedData = ''.join([chr(ord(data[i])^ord(keyData[i])) for i in xrange(len(data))])
			e.write(encryptedData)
 
		else:
			data = f.read(bytesToCopy)
			bytesToCopy = 0
			encryptedData = ''.join([chr(ord(data[i])^ord(keyData[i])) for i in xrange(len(data))])
			e.write(encryptedData)
			
		
		percent = 100*(FileSize-bytesToCopy)/FileSize
		if  percent_show != percent:
			percent_show = percent
			sys.stdout.write( "\rXORing %" + str(percent) )
			sys.stdout.flush()

	e.close()
	f.close()
	print 
	return ofile

def enable_telnet( FileTarget ):
	MB = 1024*1024
	FileSize = bytesToCheck = os.stat( FileTarget )[6]
	ifile = open( FileTarget, "r+b" )
	ifile.seek(0)
	location = ifile.tell()
	while ifile.tell() < FileSize:
		location = ifile.tell()
		if( location > 24):
			location -= 24	# recover string if its on MB border
		ifile.seek( location )
		data = ifile.read( MB )
		found = data.find( "#Remove engine logging." )
		if found != -1 :
			print
			print 'Found on :', location+found
			print 'Patching File...'
			ifile.seek( location + found )
			ifile.write( ';/etc/telnetd_start.sh&' )
			ifile.close()
			print 'Patch Complete.'
			return True
		else :
			sys.stdout.write( "\rSearching %" + str(100*location/FileSize) )
			sys.stdout.flush()
	print
	return False

print "SamyGo Firmware Patcher v" + str(version) + " (c) 2009 Erdem U. Altinyurt"
print
print '                   -=BIG FAT WARNING!=-'
print '            You can brick your TV with this tool!'
print 'Authors accept no responsibility about any damage on your devices!'
print
if len(sys.argv) != 2:
	print "For use this scripty, you have to extract your firmware to a directory first!"
	print "usage: python " + sys.argv[0] + " <path to extracted directory from firmware>"
	print "example: python " + sys.argv[0] + " ./T-CHL7DEUC/"
	print
	
else:
	if os.path.isdir( sys.argv[1] ):
		realdir = os.path.realpath( sys.argv[1] )
		key = open( realdir + '/image/info.txt' , 'r' ).read().split(' ')[0];
		print 'Detected XOR key is :',key
		targetfile = realdir+'/image/exe.img.enc' 
		if os.path.isfile( targetfile ):
			print "Decrypting with XOR"
			decfile = xor( targetfile, key )
			if  enable_telnet( decfile ):
				print "Telnet Enabled on image"
				print "Calculatin new CRC : ",
				cfil = open( decfile, 'rb' )
				crc = binascii.crc32('')
				crc = binascii.crc32(cfil.read(),crc)
				print "%x" % crc
				valfilename = realdir + '/image/validinfo.txt'
				valfile = open(valfilename, 'r+')
				loc = valfile.read().find('exe.img_')
				valfile.seek( loc+8 )
				print "Updating " + realdir + '/image/validinfo.txt with new CRC'
				valfile.write( "%x" % crc )
				print "Encrypting with XOR "
				decfile_new = xor( decfile, key )
				os.remove( targetfile )
				os.remove( decfile )
				os.rename( decfile_new, targetfile )
				print 'Operation successfully completed.'
				print 'Now you can write this directory to the Flash disk.'
				print
				print '            -=BIG FAT WARNING!=- \a'
				print 'You can brick your TV with this tool!'
				print 'Authors accept no responsibility about any damage on your TV!'
				print 'project home: http://SamyGo.sourceforge.net'
				print
			else:
				print 'Error: "#Remove engine logging." string not found on image.'
				print 'Probably this file is already patched or encrypted with SSL'
		else:
			print 'No image/exe.img.enc file in directory of ' + sys.argv[1]
	else:
		print "No valid directory with name of " + sys.argv[1]
		
