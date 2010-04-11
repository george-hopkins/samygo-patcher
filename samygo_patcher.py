#!/usr/bin/env python

#    SamyGO Samsung TV Firmware Telnet Enable Patcher
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
#version = 0.06 #Fixed the CRC sign problem. Thanks atempbloggs for indicating bug.
#version = 0.07 #Added NewAge's VideoAR Fix v2 for T-CHL7DEUC v2004.1 Firmware and patch code improvements.
#version = 0.08 #Added  VideoAR Fix v1 for T-CHU7DEUC Firmware version 2004.0 and 2008.2
#version = 0.09 #Added  VideoAR Fix v1 for T-CHL7DEUC Firmware version 2005.0
version = 0.10 #Added  VideoAR Fix v1 for T-CHU7DEUC Firmware version 2009.0

import os
import sys
import binascii
import hashlib
import subprocess
import shutil

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
	vrs = '1'
	print 'MD5 of Decrypted image is :', md5dig
	if md5dig == '9b4d11ddc6bd41156573ae61d1660fdf':
		print 'Firmware: T-CHL7DEUC version 2005.0 for LEXXB65X Devices Detected.'
		#(Address, Old Value, New Value)
		#773000 exeDSP Head
		patch =[( 0x1AC67F0, '01', '04' ),	
					( 0x1AC67F8, '02', '01' ),
					( 0x1AC6AF8, '01', '03' ),
					( 0x1AC6B04, '02', '04' ),
					( 0x1AC6B08, '01', '03' )]
					
	elif md5dig == '8060752bd9f034816c38408c2edf11b5':
		print 'Firmware: T-CHL7DEUC version 2004.1 for LEXXB65X Devices Detected.'
		#Compatible Firmwares 2004.1 and 2005.0 share same exeDSP and exactly on same location.
		#(Address, Old Value, New Value)
		#773000 exeDSP Head
		#patch =[( 0x1AC5790, '01', '04' ),	
		#			( 0x1AC5798, '02', '01' ),
		#			( 0x1AC5A98, '01', '03' ),
		#			( 0x1AC5AA4, '02', '04' ),
		#			( 0x1AC5AA8, '01', '03' )]
		#v2
		vrs = '2'
		patch = [( 0x170180C, 							'020050e36c00000a030050e36100000a010050e32d00000a0030a0e35c708de560608de558308de554308de558c09de55c', 						'0a10a0e10820a0e1b82e43eb0810a0e10a20a0e100a8a0e12aa8a0e12088a0e1650000ea0180a0e102a0a0e158c09de55c' ),
					( 0x17019F4, '8f', '8d' ),
					( 0x1AC5790, '010053e30100000a020053e30400000a1c', '0300a0e1b91e34eb030000ea0400000a1c' ),
					( 0x1AC5A68, '10', '30' ),
					( 0x1AC5A74, 							'0030a0e3013064e50600a0e30410a0e128d7dbeb000050e30c00000a1730dde5010053e3013083021730cd050200000a020053e30130430217', 							'0150a0e10030a0e3013064e50600a0e30410a0e127d7dbeb000050e30b00000a1700dde50510a0e1041e34eb1700cde5010000ea0130430217' ),
					( 0x1AC5ACC, '10', '30' ),
					( 0x27CD280, 							'480044004d0049002d0043004500430031000000480044004d0049002d0043004500430032000000480044004d0049002d0043004500430033000000480044004d0049002d0043004500430034000000480044004d0049002d0043004500430035000000480044004d0049002d0043004500430036000000480044004d0049002d0043004500430037000000480044004d0049002d0043004500430038000000480044004d0049002d0043004500430039000000480044004d0049002d00430045004300310030000000330044002d0065006600660065006b0074000000320044002d006b006f006e0076006500720074006500720069006e0067000000330044002d0065006600660065006b00740000004100760000004c00e40067006500320000004c00e400670065003100000041006e00740065006e006e002f004b006100620065006c0000005600e40078006c0061002000740069006c006c00200061006e00740065006e006e0000005600e40078006c0061002000740069006c006c0020006b006100620065006c0000005600e40078006c0061002000740069006c006c00200073006100740065006c006c006900740000004100750074006f002000570069006400650000004100750074006f006c0061006700720061000000410056000000410056003100000041005600320000004100560033000000410056003400000042006c007500650074006f006f007400680000004e006f0074002000550073006500000046007200e5006e006b006f00700070006c0069006e00670020006100760020006800f60072006c0075007200000041006e0073006c00750074006e0069006e00670020006600f600720020006800f60072006c007500720000005400650078007400720065006d007300610000004c00e400670067002000740069006c006c002f0054006100200062006f007200740020006b0061006e0061006c00000049006e0066006f0072006d006100740069006f006e0000004c00e500730074002f005500700070006c00e50073007400000041006e00670065002000500049004e0000004c00e5007300200061006b007400750065006c006c0020006b0061006e0061006c0000004b0061006e0061006c0065006e0020006c00e5007300740000004c00e50073002000750070007000200061006b007400750065006c006c0020006b0061006e0061006c0000004b0061006e0061006c0065006e0020007500700070006c00e5007300740000003a00000043006f006d0070006f006e0065006e007400000043006f006d0070006f006e0065006e0074003100000043006f006d0070006f006e0065006e0074003200000043006f006d0070006f006e0065006e0074003300000043006f006d0070006f006e0065006e0074003400000043006f006e00740065006e00740020004c00690062007200610072007900000044004e0053006500000044', 							'0e0050e30000a0231eff2f21010050e35310a0030400000a020050e314119f15000191171eff2f115410a0e308019fe5016aa7ea050051e30700001a010080e2ff0000e2030050e30400a0031eff2f010e0050e30100a0231eff2fe1010050e30d00a0931eff2f91010040e2ff0000e2030050e30200a0031eff2fe1f0412de90030a0e10100a0e1b0109fe50240a0e1001091e5010051e31e6da013d25f46129c609f05035ca003010053e3020053131d00000a040053e30600a0011400000a051043e2080051e31200008a74009fe5031190e7380040e2030190e7940000e0790000eb0070a0e1960400e00480a0e10710a0e1740000eb050050e10040a0e10600a0910300009a950700e00810a0e16d0000eb0540a0e10008a0e12008a0e1040880e1f041bde81eff2fe1010053e3f8ffff1aeaffffea042606029816600204c75f025605000074260602013090e12100004a0020b0e3a03071e01a00003a203271e00f00003a203471e00100003a00c0a0e3200000eaa03371e0810340200220b2e0203371e0010340200220b2e0a03271e0810240200220b2e0203271e0010240200220b2e0a03171e0810140200220b2e0203171e0010140200220b2e0a03071e0810040200220b2e0011050e00010a0310200a2e01eff2fe1022111e20010614240c032e000006022203271e01d00003a203471e00f00003a0113a0e1203471e03f2382e30b00003a0113a0e1203471e03f2682e30700003a0113a0e1203471e03f2982e30113a0213f2c8223003071e21d00002a2113a021a03371e0810340200220b2e0203371e0010340200220b2e0a03271e0810240200220b2e0203271e0010240200220b2e0a03171e0810140200220b2e0203171e0010140200220b2e0ebffff2aa03071e0810040200220b2e0011050e00010a0310200a2e0cccfb0e100006042001061221eff2fe1cccfb0e10000604201402de90000b0e30000a0e10240bde81eff2fe10020b0e3203271e0b3ffff3a203471e0a5ffff3a00c0a0e3c4ffffea460075006c006c002000530063007200650065006e00000034003a00330000004e006f006e00200041006e0061006d006f007200700068000000310036003a003900000041006e0061006d006f00720070006800000031002e00380035003a003100000032002e00330035003a003100000032002e00330037003a003100000032002e00330039003a003100000032002e00370036003a003100000000000000000000000000000000000000682506028025060288250602a2250602ac250602be250602cc250602da250602e8250602f625060201000000010000000100000001000000010000000400000068350000100000001f070000b9000000e95b0000ed000000ef000000140100000100000001000000010000000100000001000000030000001027000009000000e803000064000000102700006400000064000000640000006500000044' )]

	elif md5dig == '63194257f8a9368f06a0af58cdee1c62':
		print 'Firmware: T-CHEAUSC version 1012.3 for LNXXB65X Devices Detected.'
		#(Address, Old Value, New Value)
		patch =[	( 0x1989BF8, '01', '04' ),
					( 0x1989C00, '02', '01' ),
					( 0x1989EFC, '01', '03' ),
					( 0x1989F08, '02', '04' ),
					( 0x1989F0C, '01', '03' )]
	
	elif md5dig == '236cd11def19b92107593105cda4e0c7':
		print 'Firmware: T-CHU7DEUC version 2004.0 for UEXXB70XX Devices Detected.'
		patch =[ ( 0x22AEDE8, '01', '04' ),
					( 0x22AEDF0, '02', '01' ),
					( 0x22AF0F0, '01', '03' ),
					( 0x22AF0FC, '02', '04' ),
					( 0x22AF100, '01', '03' ) ]
					
	elif md5dig == '66c3681faf32527fd9330364203bf245':
		print 'Firmware: T-CHU7DEUC version 2008.2 for UEXXB70XX Devices Detected.'
		patch =[ ( 0x1AC5758, '01', '04' ),
					( 0x1AC5760, '02', '01' ),
					( 0x1AC5A60, '01', '03' ),
					( 0x1AC5A6C, '02', '04' ),
					( 0x1AC5A70, '01', '03' )]
	elif md5dig == 'a1b3e35f97881703c468a7a72bb759e8':
		print 'Firmware: T-CHU7DEUC version 2009.0 for UEXXB70XX Devices Detected.'
		#773000 exeDSP Head
		patch =[( 0x1AC67B8, '01', '04' ),	
					( 0x1AC67C0, '02', '01' ),
					( 0x1AC6AC0, '01', '03' ),
					( 0x1AC6ACC, '02', '04' ),
					( 0x1AC6AD0, '01', '03' )]
			
	else :
		print "Oops!: This firmware is unknown for VideoAR patch. Skipped!"
		print "Please visit forum for support."
		print "SamyGo Home: http://SamyGo.sourceforge.net"
		return 0
	
	read_pass = True
	for i in patch:	#this is unneccessary round, 1-1 checking for each byte if its correct.
		ifile.seek( i[0] )
		Readed = ifile.read( len( binascii.unhexlify( i[1] ) ) )
		if binascii.unhexlify(i[1]) != Readed:
			read_pass = False
			print "Error on reading byte: %X" %  i[0]
			print "Need : " , i[1]
			print "Read : " , binascii.hexlify(Readed)
			break
		
	if read_pass:	#if all bytes are correct, than patch it
		for i in patch:
			ifile.seek( i[0] )
			ifile.write( binascii.unhexlify(i[2]) )
		print 'VideoAR Fix v' + vrs + ' Patched on image.'
		print
		
	else:				#if there is difference on bytes give error
		print "Warning! This Firmware or script is CORRUPT!"
		print "OPERATION ABORTED!"
		return -1

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
	pv = patch_VideoAR( decfile, md5digg )
	pt = patch_Telnet( decfile )
	pt = 0
	
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
print '         project home: http://SamyGO.sourceforge.net'
print
if len(sys.argv) != 2:
	print "For use this scripty, you have to extract your firmware to a directory first!"
	print "usage: python " + sys.argv[0] + " <path to extracted directory from firmware>"
	print "example: python " + sys.argv[0] + " ./T-CHL7DEUC/"
	print
	
else:
	SamyGO( sys.argv[1] )
		
