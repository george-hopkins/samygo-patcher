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
#version = 0.02 #Added & after telnet init for run exeDSP if telnet script returns error or not.
#version = 0.03 #Added newagehun's VideoAR fix for T-CHL7DEUC v2004.1 Firmware and CLI UI improvements.
#version = 0.04 #Added VideoAR fix for T-CHEAUSC Firmware version 1012.3 (Usualy named as 2009_DTV_1G_firmware.exe)
#version = 0.05 #Fixed file open mode by forcing binary for windows. Thanks dolak for indicating bug.
version = 0.06 #Fixed the CRC sign problem. Thanks atempbloggs for indicating bug.

import os
import sys
import binascii
import hashlib

#XOR file with given key, (slow!)
def xor(fileTarget, key):	
	md5digg = hashlib.md5()

	ifile = fileTarget
	ofile = fileTarget+".xor"
 
	if os.path.isfile(key):
		kf = open(key)
		keyData = kf.read()
		kf.close()
	else:
		keyData = key
 
	e = open(ofile, "wb")
	f = open(ifile, "rb")
 
	FileSize = bytesToCopy = os.stat( fileTarget )[6]
	percent_show = 0

	sys.stdout.write( " %00" )
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
			
		md5digg.update( encryptedData )
		
		percent = 100*(FileSize-bytesToCopy)/FileSize
		if  percent_show != percent:
			percent_show = percent
			sys.stdout.write( "\b\b%02d" % percent )
			sys.stdout.flush()

	e.close()
	f.close()
	print 
	return ofile, binascii.hexlify(md5digg.digest())

#Search "#Remove engine logging." string and replaces with ";/etc/telnetd_start.sh&"
def patch_Telnet( FileTarget ):
	print 'Applying Telnet Patch...'
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
			print 'Telnet Suitable Location Found on Offset :', location+found
			print 'Patching File...'
			ifile.seek( location + found )
			ifile.write( ';/etc/telnetd_start.sh&' )
			ifile.close()
			print "Telnet Enabled on image."
			return True
		else :
			sys.stdout.write( "\rSearching %" + str(100*location/FileSize) )
			sys.stdout.flush()
	ifile.close()
	print
	print 'Oops!: "#Remove engine logging." string not found on image.'
	print 'Probably this firmware is already patched or firmware is encrypted with SSL'
	print 'Telnet Patch not applied.'
	return False

#Detect exact file using MD5 Hasf of it.
#Than changes defined bytes with given values.
def patch_VideoAR( FileTarget, md5dig ):
	print 'Applying VideoAR Patch...'
	FileSize = bytesToCheck = os.stat( FileTarget )[6]
	ifile = open( FileTarget, "r+b" )
	patch = []
	print 'MD5 of Decrypted image is :', md5dig
	if md5dig == '8060752bd9f034816c38408c2edf11b5':
		print 'Firmware: T-CHL7DEUC version 2004.1 for LEXXB65X Devices Detected.'
		#(Address, Old Value, New Value)
		patch =[	( 0x1AC5790, '\x01', '\x04' ),
					( 0x1AC5798, '\x02', '\x01' ),
					( 0x1AC5A98, '\x01', '\x03' ),
					( 0x1AC5AA4, '\x02', '\x04' ),
					( 0x1AC5AA8, '\x01', '\x03' )]
					
	elif md5dig == '63194257f8a9368f06a0af58cdee1c62':
		print 'Firmware: T-CHEAUSC version 1012.3 for LNXXB65X Devices Detected.'
		#(Address, Old Value, New Value)
		patch =[	( 0x1989BF8, '\x01', '\x04' ),
					( 0x1989C00, '\x02', '\x01' ),
					( 0x1989EFC, '\x01', '\x03' ),
					( 0x1989F08, '\x02', '\x04' ),
					( 0x1989F0C, '\x01', '\x03' )]
#	elif Remember! Convert exeDSP values to Image values, or Image will be corrupt!

	if len(patch) == 0 :	#if no md5 definition match with firmware, skip the patch.
		print "Oops!: This firmware is unknown for VideoAR patch. Skipped!"
		print "Please visit forum for support."
		print "SamyGo Home: http://SamyGo.sourceforge.net"
		return 0

	else:	#if patch available
		read_pass = True
		for i in patch:	#this is unneccessary round, 1-1 checking for each byte if its correct.
			ifile.seek( i[0] )
			if i[1] != ifile.read( 1 ):		
				read_pass = False
				break
			
		if read_pass:	#if all bytes are correct, than patch it
			for i in patch:
				ifile.seek( i[0] )
				ifile.write( i[2] )
		else:				#Give error if MD5 is same but bytes
			print "Warning! This Firmware is CORRUPT!"
			print "DO NOT FLASH YOUR TV WITH PATCHED FIRMWARE!"
			print "OPERATION ABORTED!"
			return -1
		
		print 'VideoAR Patched on image.'
		print 
		ifile.close()
		return 1

def calculate_crc( decfile ):
	print "Calculatin new CRC : ",
	cfil = open( decfile, 'rb' )
	crc = binascii.crc32('')
	crc = binascii.crc32(cfil.read(),crc) & 0xffffffff
	print "%x" % crc
	return crc

#Main function, receives firmware's root directory
def SamyGO( in_dir ):
	if not os.path.isdir( in_dir ):
		print "No valid directory with name of " + in_dir
		return False
	
	realdir = os.path.realpath( in_dir )
	key = open( realdir + '/image/info.txt' , 'r' ).read().split(' ')[0];	#Reading firmware name for using as XOR decryption key
	print 'Detected XOR key is :',key
	targetfile = realdir+'/image/exe.img.enc' 
	if not os.path.isfile( targetfile ):
		print 'No image/exe.img.enc file in directory of ' + in_dir
		return False

	print "Decrypting with XOR ",
	decfile,md5digg = xor( targetfile, key )
	print
	pt = patch_Telnet( decfile )
	print
	pv = patch_VideoAR( decfile, md5digg )
	
	if( (pt or pv) and pv != -1 ):	#if Telnet or Video patch applied 
		crc = calculate_crc( decfile )
		validfile = open(realdir + '/image/validinfo.txt', 'r+')
		loc = validfile.read().find('exe.img_')
		validfile.seek( loc+8 )
		print "Updating " + realdir + '/image/validinfo.txt with new CRC.'
		validfile.write( "%x" % crc )
		validfile.close()
		print
		
		print "Encrypting with XOR ",
		decfile_new, tmp = xor( decfile, key )
		os.remove( targetfile )
		os.remove( decfile )
		os.rename( decfile_new, targetfile )
		print 'Operation successfully completed.'
		print 'Now you can flash your TV with ' + in_dir +' directory.'

print "SamyGo Firmware Patcher v" + str(version) + " (c) 2009 Erdem U. Altinyurt"
print
print '                   -=BIG FAT WARNING!=-'
print '            You can brick your TV with this tool!'
print 'Authors accept no responsibility about ANY DAMAGE on your devices!'
print '         project home: http://SamyGo.sourceforge.net'
print
if len(sys.argv) != 2:
	print "For use this scripty, you have to extract your firmware to a directory first!"
	print "usage: python " + sys.argv[0] + " <path to extracted directory from firmware>"
	print "example: python " + sys.argv[0] + " ./T-CHL7DEUC/"
	print
	
else:
	SamyGO( sys.argv[1] )
		
