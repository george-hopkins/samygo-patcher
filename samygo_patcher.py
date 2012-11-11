#!/usr/bin/env python

#    SamyGO Samsung TV Firmware Patcher
#    Copyright (C) 2010-2011  Erdem U. Altunyurt

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    SamyGo Home Page: http://www.samygo.tv

#version = 0.01 #initial Release
#version = 0.02 #Added & after telnet init for run exeDSP if telnet script returns error or not.
#version = 0.03 #Added newagehun's VideoAR fix for T-CHL7DEUC v2004.1 Firmware and CLI UI improvements.
#version = 0.04 #Added VideoAR fix for T-CHEAUSC Firmware version 1012.3 (Usualy named as 2009_DTV_1G_firmware.exe)
#version = 0.05 #Fixed file open mode by forcing binary for windows. Thanks dolak for indicating bug.
#version = 0.06 #Fixed the CRC sign problem. Thanks atempbloggs for indicating bug.
#version = 0.07 #Added NewAge's VideoAR Fix v2 for T-CHL7DEUC v2004.1 Firmware and patch code improvements.
#version = 0.08 #Added  VideoAR Fix v1 for T-CHU7DEUC Firmware version 2004.0 and 2008.2
#version = 0.09 #Added  VideoAR Fix v1 for T-CHL7DEUC Firmware version 2005.0
#version = 0.10 #Added  VideoAR Fix v1 for T-CHU7DEUC Firmware version 2009.0
#version = 0.11 #Added Telnet or Advanced Mode switch.
#version = 0.12 #Fixed not make encryption if no VideoAR fix situation.
#version = 0.13 #Added  VideoAR Fix v1 for T-CHU7DEUC Firmware version 3000.G
#version = 0.14 #Added  VideoAR Fix v1 and WiseLink hack for T-CHL5DEUC Firmware version 2008.0
#version = 0.15 #Added Automatic VideoAR Fix v1 Patching for All FAT exe.img images.
#version = 0.16 #Added CI+ devices support (Requires Crypto Package for python). XOR acceleration if Crypto Package found. And Fixed Validinfo update if CRC is smaller than 8 significant byte.
#version = 0.17 #Placed VideoARFix switch. Firmware ID.Shown on Patch screen. exeDSP extracted with Firmware Name. Fixed MD5 hex diggest reporting on slow xor enigne.
#version = 0.18 #Fixed T-CHL5DEUC's Windows patch process.
#version = 0.19 #Changed XOR key retrieve way. Now ket readed directly from exeDSP... Compatibility for T-CHEAEAC 2005 FW.for LAxxB650T1R
#version = '0.20' #Added Auto Big & Colorful Subtitle Patch, Modulerized code flow with Extract_exeDSP & Inject_exeDSP functions. Added VideoAR Fix v1 for CI+ devices.
#version = '0.21' #Added A Series T-RBYDEUC 1013.1 arfix-sh4 1.1 by tom_van & Fixed fat16 FAT finding.
#version = '0.22' #Added USB SamyGO/rcSGO starter for T-RBYDEUC by tom_van, T-CHL7DEUC 2004.1 BigSubTitles, SquashFS image support on linux. (T-CHL5DEUC & T-CHE6ASUC support). Also added automated Enable Wiselink Player Hack on T-CHL5DEUC firmwares. Cosmetic fixes...
#version = '0.23' #Fixed FAT16 exeDSP injection. Added T-CHE6AUSC wiselink hack.
#version = '0.24' #Fixed syntax in path string for non encrypted images.
#version = '0.25Beta' #Fat File Extractor & Injector code changed for code. Added Telnet support to LAxxB650 CHEAEAC series.
#Need to test with SquashFS telnet after release!
#version = '0.26' #Upgrade arfix-sh4 for T-RBYDEUC 1013.1 to version 1.2 (tom_van)
#version = '0.30' #Added C & D image decryption support. SamyGO function partitioned...
#version = '0.31Beta' #Added E-Series (Echo.P) image decryption support, and prepare for other E-Series (Echo.B, X10, X9).
#version = '0.31BetaBlue' #Added support for B-FIR* not all tested!!!.
#version = '0.32' #cleanup on bd-players.
#version = '0.33' #Key for T-MST10P added.
version = '0.34' #Key for ECBHRDEUC, FIRBPEWW (BD-E8???, BD-E6???).
import os
import sys
import binascii
import hashlib
import subprocess
import urllib
import struct
import stat
import time

#XOR file with given key, (slow!)
def xor(fileTarget, key=''):
	md5digg = hashlib.md5()

	ifile = fileTarget
	if fileTarget[fileTarget.rfind( '.' ):] == '.img':
		ofile = fileTarget+'.enc'
	elif fileTarget[fileTarget.rfind( '.' ):] == '.enc':
		ofile = fileTarget[:fileTarget.rfind( '.' )]
	else:
		ofile = fileTarget+'.xor'

	e = open(ofile, "wb")
	f = open(ifile, "rb")

	if key!='':
		keyData = key
	else:
		f.seek(-40, 2)
		a = f.read()
		f.seek(0)
		a = a[a.find( 'T-' ):]
		keyData = a[:a[1:].find( 'T-' )+1]

	print "XOR Key : ",  keyData


	FileSize = bytesToCopy = os.stat( fileTarget )[6]
	percent_show = 0

	CryptPackage = False
	try:
		from Crypto.Cipher import XOR
		print 'Crypto package found, using fast XOR engine.'
		CryptPackage = True
		cip_xor = XOR.new( keyData )
		the_image_data = cip_xor.decrypt( f.read() )
		md5digg.update( the_image_data )
		e.write( the_image_data )
		e.close()
		f.close()
		print
		return ofile, md5digg.hexdigest(),keyData
	except ImportError:
		print 'Crypto package not found, using slow XOR engine.'
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
		return ofile, md5digg.hexdigest(),keyData

#partial elfread utility in python, by Erdem Umut Altinyurt 2009 (C)
def ReadELF( filename ):
	#fl = open( 'SamyGO.exeDSP', 'rb' )
	fl = open( filename, 'rb' )

	ELF = fl.read( 52 )
	if not ((ELF[0:16] == '\x7F\x45\x4C\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00') and (ELF[ 18:20 ] == '\x28\x00')): #ARM Machine code
		print 'Not an ARM ELF exeDSP file'
		sys.exit()

	#print 'ARM ELF exeDSP File Detected'
	SectionHeader_TableOffset, = struct.unpack('<I', ELF[32:36])
	SectionHeader_EntrySize,SectionHeader_NumberOfEntries,SectionHeader_StringIndexNumber, = struct.unpack('<HHH', ELF[46:52])

	#print 'SectionHeader_TableOffset: 0x%X' % SectionHeader_TableOffset

	#Creating Section Header Table
	shtable=[]
	for i in range(0,SectionHeader_EntrySize*SectionHeader_NumberOfEntries, SectionHeader_EntrySize):
		fl.seek( i+SectionHeader_TableOffset )
		SectionHeader = fl.read( 40 )
		#shdr = (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize,)
		shdr = [i for i in struct.unpack('<IIIIIIIIII', SectionHeader)]
		shtable.append( shdr )

	#Getting to Stream Header String Index Table
	shstrtab = shtable[ SectionHeader_StringIndexNumber ]
	fl.seek( shstrtab[4] )
	shstrtab = fl.read( shstrtab[5] )

	#Updating first fields of Stream Header Table with names from Stream Header String Index Table
	shtable=[ [shstrtab[i[0]:].split('\x00')[0]]+i[1:] for i in shtable]
#	for i in shtable:
#		print i

	dynstrtab = [i for i in shtable if i[0]=='.dynstr'][0]
	fl.seek( dynstrtab[4] )
	dynstrtab = fl.read( dynstrtab[5] )

	#Gettin dynamic symbol table adress, size and entry sizes
	dynsymtab = [i for i in shtable if i[0]=='.dynsym'][0]
	#Creating dynamic symbol table
	symtab=[]
	for i in range(0,dynsymtab[5],dynsymtab[9] ):
		fl.seek( i+dynsymtab[4] )
		SectionHeader = fl.read( dynsymtab[9] )
		#shdr = (st_name, st_value, st_size, st_info, st_other, st_shndx)
		shdr = [ i for i in struct.unpack('<IIIBBH', SectionHeader)]
		symtab.append( shdr )

	#Updating first fields of symbol table with names
	symtab=[ [dynstrtab[i[0]:i[0]+100].split('\x00')[0]]+i[1:] for i in symtab]

	#grep _ZNK23CToolMmbDisplaySizeItem function first
	#sym_DisplaySizeItem = [i for i in symtab if i[0].find('_ZNK23CToolMmbDisplaySizeItem')>=0 ]
	#for i in sym_DisplaySizeItem
	#	print i
	return symtab


#Search "#Remove engine logging." string and replaces with ";/etc/telnetd_start.sh&"
def patch_Telnet( FileTarget ):
	print 'Applying Telnet Patch...'
	filepath = Fat_Extract( FileTarget, "RC~1    LOC" )
	rclocalfile = open( filepath , 'r+b')
	rclocal = rclocalfile.read()

	if rclocal.split()[-1].endswith('#via SamyGO Firmware Patcher'):
		print 'This file is already patched via SamyGO Firmware Patcher'
		rclocal = rclocal.split()[:-1]

		a=''
		for i in rclocal:
			a+=i+'\n'
		rclocal = a # removes old patcher line

	var = raw_input("Enable Telnet or Advanced Mode or nothing on image( T/a/n )? ")

	if var == 'a' or var == 'A':
		rclocal += '\n/mtd_rwarea/SamyGO.sh& #via SamyGO Firmware Patcher\n'
		print "TV will initiate '/mtd_rwarea/SamyGO.sh' script on each start."
		print
	elif var == 'n' or var == 'N':
		print "Telnet patch skipped."
		print
		return False
	else:
		rclocal += '\n/etc/telnetd_start.sh& #via SamyGO Firmware Patcher\n'
		print "Telnet Enabled on image."
		print

	print 'Patching File...'
	rclocalfile.seek(0)
	rclocalfile.truncate(0)
	rclocalfile.write( rclocal )
	rclocalfile.close()
	return Fat_Inject( FileTarget, "RC~1    LOC", filepath )

def patch_TelnetRBYDEUC( FileTarget ):
	print 'Applying Telnet Patch...'
	MB = 1024*1024
	FileSize = bytesToCheck = os.stat( FileTarget )[6]
	ifile = open( FileTarget, "r+b" )
	ifile.seek(0)
	location = ifile.tell()
	while ifile.tell() < FileSize:
		location = ifile.tell()
		if( location > 40):
			location -= 40	# recover string if its on MB border
		ifile.seek( location )
		data = ifile.read( MB )
		found = data.find( "## mount -n -t usbfs none /proc/bus/usb\n" )
		if found != -1 :
			print
			print 'Suitable Location Found for Script injection on Image Offset :', location+found
			var = raw_input("Enable starting script SamyGO/rcSGO from USB or no change ( U/n )? ")

			if var == 'u' or var == 'U':
				print 'Patching File...'
				ifile.seek( location + found )
				ifile.write( '( sleep 9; /dtv/usb/sd*/SamyGO/rcSGO )&' )
				print "TV will initiate '/dtv/usb/sd*/SamyGO/rcSGO' script on each start."
				print
			else:
				print "Telnet patch skipped."
				print
				return False
			ifile.close()
			return True
		else :
			sys.stdout.write( "\rSearching %" + str(100*location/FileSize) )
			sys.stdout.flush()
	ifile.close()
	print
	print 'Oops!: "## mount -n -t usbfs none /proc/bus/usb" string not found on image.'
	print 'Probably this firmware is already patched.'
	print 'Telnet Patch not applied.'
	print
	return False

#Detect exact file using MD5 Hasf of it.
#Than changes defined bytes with given values.
def patch( FileTarget, md5dig, firmware ):
	print 'Applying Patches...'
	FileSize = bytesToCheck = os.stat( FileTarget )[6]
	patch = []
	vrs = '1'
	print 'MD5 of Decrypted image is :', md5dig
	print
	if md5dig == '8060752bd9f034816c38408c2edf11b5':
		print 'Firmware: T-CHL7DEUC version 2004.1 for LEXXB65X Devices Detected.'
		ifile = open( FileTarget, "r+b" )
		patch = [( 0x170180C, '020050e36c00000a030050e36100000a010050e32d00000a0030a0e35c708de560608de558308de554308de558c09de55c','0a10a0e10820a0e1b82e43eb0810a0e10a20a0e100a8a0e12aa8a0e12088a0e1650000ea0180a0e102a0a0e158c09de55c' ),
					( 0x17019F4, '8f', '8d' ),
					( 0x1AC5790, '010053e30100000a020053e30400000a1c', '0300a0e1b91e34eb030000ea0400000a1c' ),
					( 0x1AC5A68, '10', '30' ),
					( 0x1AC5A74, '0030a0e3013064e50600a0e30410a0e128d7dbeb000050e30c00000a1730dde5010053e3013083021730cd050200000a020053e30130430217', '0150a0e10030a0e3013064e50600a0e30410a0e127d7dbeb000050e30b00000a1700dde50510a0e1041e34eb1700cde5010000ea0130430217' ),
					( 0x1AC5ACC, '10', '30' ),
					( 0x27CD280, '480044004d0049002d0043004500430031000000480044004d0049002d0043004500430032000000480044004d0049002d0043004500430033000000480044004d0049002d0043004500430034000000480044004d0049002d0043004500430035000000480044004d0049002d0043004500430036000000480044004d0049002d0043004500430037000000480044004d0049002d0043004500430038000000480044004d0049002d0043004500430039000000480044004d0049002d00430045004300310030000000330044002d0065006600660065006b0074000000320044002d006b006f006e0076006500720074006500720069006e0067000000330044002d0065006600660065006b00740000004100760000004c00e40067006500320000004c00e400670065003100000041006e00740065006e006e002f004b006100620065006c0000005600e40078006c0061002000740069006c006c00200061006e00740065006e006e0000005600e40078006c0061002000740069006c006c0020006b006100620065006c0000005600e40078006c0061002000740069006c006c00200073006100740065006c006c006900740000004100750074006f002000570069006400650000004100750074006f006c0061006700720061000000410056000000410056003100000041005600320000004100560033000000410056003400000042006c007500650074006f006f007400680000004e006f0074002000550073006500000046007200e5006e006b006f00700070006c0069006e00670020006100760020006800f60072006c0075007200000041006e0073006c00750074006e0069006e00670020006600f600720020006800f60072006c007500720000005400650078007400720065006d007300610000004c00e400670067002000740069006c006c002f0054006100200062006f007200740020006b0061006e0061006c00000049006e0066006f0072006d006100740069006f006e0000004c00e500730074002f005500700070006c00e50073007400000041006e00670065002000500049004e0000004c00e5007300200061006b007400750065006c006c0020006b0061006e0061006c0000004b0061006e0061006c0065006e0020006c00e5007300740000004c00e50073002000750070007000200061006b007400750065006c006c0020006b0061006e0061006c0000004b0061006e0061006c0065006e0020007500700070006c00e5007300740000003a00000043006f006d0070006f006e0065006e007400000043006f006d0070006f006e0065006e0074003100000043006f006d0070006f006e0065006e0074003200000043006f006d0070006f006e0065006e0074003300000043006f006d0070006f006e0065006e0074003400000043006f006e00740065006e00740020004c00690062007200610072007900000044004e0053006500000044', 							'0e0050e30000a0231eff2f21010050e35310a0030400000a020050e314119f15000191171eff2f115410a0e308019fe5016aa7ea050051e30700001a010080e2ff0000e2030050e30400a0031eff2f010e0050e30100a0231eff2fe1010050e30d00a0931eff2f91010040e2ff0000e2030050e30200a0031eff2fe1f0412de90030a0e10100a0e1b0109fe50240a0e1001091e5010051e31e6da013d25f46129c609f05035ca003010053e3020053131d00000a040053e30600a0011400000a051043e2080051e31200008a74009fe5031190e7380040e2030190e7940000e0790000eb0070a0e1960400e00480a0e10710a0e1740000eb050050e10040a0e10600a0910300009a950700e00810a0e16d0000eb0540a0e10008a0e12008a0e1040880e1f041bde81eff2fe1010053e3f8ffff1aeaffffea042606029816600204c75f025605000074260602013090e12100004a0020b0e3a03071e01a00003a203271e00f00003a203471e00100003a00c0a0e3200000eaa03371e0810340200220b2e0203371e0010340200220b2e0a03271e0810240200220b2e0203271e0010240200220b2e0a03171e0810140200220b2e0203171e0010140200220b2e0a03071e0810040200220b2e0011050e00010a0310200a2e01eff2fe1022111e20010614240c032e000006022203271e01d00003a203471e00f00003a0113a0e1203471e03f2382e30b00003a0113a0e1203471e03f2682e30700003a0113a0e1203471e03f2982e30113a0213f2c8223003071e21d00002a2113a021a03371e0810340200220b2e0203371e0010340200220b2e0a03271e0810240200220b2e0203271e0010240200220b2e0a03171e0810140200220b2e0203171e0010140200220b2e0ebffff2aa03071e0810040200220b2e0011050e00010a0310200a2e0cccfb0e100006042001061221eff2fe1cccfb0e10000604201402de90000b0e30000a0e10240bde81eff2fe10020b0e3203271e0b3ffff3a203471e0a5ffff3a00c0a0e3c4ffffea460075006c006c002000530063007200650065006e00000034003a00330000004e006f006e00200041006e0061006d006f007200700068000000310036003a003900000041006e0061006d006f00720070006800000031002e00380035003a003100000032002e00330035003a003100000032002e00330037003a003100000032002e00330039003a003100000032002e00370036003a003100000000000000000000000000000000000000682506028025060288250602a2250602ac250602be250602cc250602da250602e8250602f625060201000000010000000100000001000000010000000400000068350000100000001f070000b9000000e95b0000ed000000ef000000140100000100000001000000010000000100000001000000030000001027000009000000e803000064000000102700006400000064000000640000006500000044' )]
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
			ifile.close()
			print 'VideoAR Fix v2 Patched on image.'

			exeDSPFileName = Fat_Extract( FileTarget, "exeDSP" )
			if exeDSPFileName != '':
				#a = Patch_VideoAR_v1_Fix( exeDSPFileName ) #v2 already!
				if Patch_Big_Subtitles( exeDSPFileName ):
					Fat_Inject( FileTarget, "EXEDSP", exeDSPFileName )

		else:				#if there is difference on bytes give error
			print "Warning! This Firmware or script is CORRUPT!"
			print "OPERATION ABORTED!"
			ifile.close()
			return -1


	elif md5dig == '2f2b172b0ce35e40326ab1594c131f15':
		print 'Firmware: T-RBYDEUC version 1013.1 for A Series.'
		exeDSPFileName = Fat_Extract( FileTarget, "exeDSP" )
		ifile = open( exeDSPFileName, "r+b" )
		patch = [
			( 0x016f43c, '862fe62f224fb87fb87ff36ee36110714211e362107200e11a12e362507200e11512e362507200e11612e36250729f911312e36250729c911412e362107200e11b12e362107200e11c12e362107200e11d12e362107200e11e12e362107200e11f12e362507200e11012e362507200e11112e362507200e112123fd11262e36110712d113dd11262e36110712e113cd2e36110711251122239d112600188018916a1090037d1136437d10b410900e36110711d505a402df208e0ec3004702af03bf01d5111410b8930c709f309f208e0ec3009f508f4fc7020f404704af05bf008e0ec3009f308f2fc70bdf210e05a01160ee36110711e525a422df2047e2afe3bfe1e511141098920c709f309f2e9f5e8f4fc7e20f4047e4afe5bfee9f3e8f2fc7ebdf20df12592ec321ad16641fc7110e0e6f213f22cf11af2e361507113505a402df2e361507114525a422df11291ec312cf313f33cf11af1e36110711d5118211a89e36110711e51182114a009008007380488008c000c02210210022102707901023cf1490140cb4101000000000000f04194f49901188be362107200e11f12e362507200e11012e3625072e361507113511112e3625072e36150711451121241d16641fc71f0a009007a91ec317992ec3218f228f115f2018939a00900e362107200e11f12e36150711457e36150711352e36110711e5117021a01e362107232d313642d550b43090073610831e362507201411012e3625072e361507113511112e36150711352e36110711e5117021a03e3675077e361107123d233641d550b42090002171fd16641fc71ada00900e36150711357e36150711452e36110711d5117021a01e362107217d313642e550b43090073610831e362107201411f12e362507200e11012e36150711452e36110711d5117021a03e3675077e36110710ad233641e550b4209000117e3625072e36150711451121203d16641fc7174a0090088008c0098f49901801d3f0114d112600288f38b13d1136413d10b410900e36110711d5118210489e36110711e5118211c8be362107200e11f12e362507200e11012e3625072e361507113511112e3625072e36150711451121245a009000900707901025cf1490140cb4101e361507113521fe11b6123601d4003612c312141136399d112621fe11b6123671d4773612c31214133621832e36110712f11e361507114521fe11b6123601d4003612c31214113638dd112621fe11b6123671d4773612c31214133621832e36150712011e3625072e36110711d511112e3625072', '862f4368962f03e3a62fb62fc62fd62fe62f224f73d474d2426074d13d402e0d73d0d82d1269026b098fec7f226d71d1d82d71d4018b225d70d40b4109000fe2273b008910eb08e55739028909e90aa08360c096603b068f8360bd977039038f0288ba99836002880b8f02e2b391173b008b136bb1911739008b1369b36839a09360fd782638078d037803ea5cd0a592ad488e051ca009005ad88260094009400fc9fe702630078d027003ee56dc9592ed40ce050ca009009191103b078fb3658e933039038f93628b9501a0090093628396809367054dd71a0137021a044731038b0b47336809a0090013640b472365036863606f911738008b13686b94e1e36b928834436c3d4c4c3c214c2730018f036e236e3ed02365e835d364536a3d4a5c3af366f3650b401075214a0820038930d038d40b40090037d0f365d3641075f3660b400876082003892ad033d40b40090033d0f366d3640b4000e50820038924d030d40b4009002fd0f366d36408760b4000e5082003891ed02cd40b4009001cd2f07f1fd19367822f126528d4e11fc21fa31f0b42b366fc7fd364922fb36724d900e5c11fa21f831fe41f0b4900e60820048d147f0fdb1fd40b4b090000e0147f264ff66ef66df66cf66bf66af669f6680b0009008007400438048403d00240020003e801210260032102100221020c022102409d41018cf65600acf65600b0f75600d81d2102b8f75600801d3f0168619a00ccf6560008659a00ecf6560050809a0010f756006c7d9a0030f7560054f75600587e9a0090f75600806003d1002101d12b410900e099b000d81d210253657453697a65206d6d5f566964656f496e666f5374727563745b305d0a000053657453697a65206d6d5f566964656f496e666f5374727563745b315d0a000053545649445f476574496e70757457696e646f774d6f6465204572726f720a0053545649445f4765744f757470757457696e646f774d6f6465204572726f720a0000000053545649445f536574496e70757457696e646f774d6f6465204572726f720a0053545649445f5365744f757470757457696e646f774d6f6465204572726f720a00000000617266697820312e322053657453697a65204d504547204152202530782c20496e2025647825642c204f75742025647825642d25642d25640a00000053545649445f53657453697a65204572726f720a0000000032002e00320031003a0031000000000000000000460000000000000047000000b00400001d0000004006000019000000c5070000a8f75600' ),
			( 0x033d334, '090009000900090009000900', '01d000e102a01220d81d2102' ),
			( 0x0340320, '40604060', '40204060' ),
			( 0x0340470, '40d37300', '34d37300' ),
			( 0x0704e8c, 'e099b000', '78f65600' ),
			( 0x0916520, '862f73e5e62f01e7224f1bd0fc7ff36ee368037819d40b40836608200a8d00e080611c600188018d0288198914d015d40b4046e5047ee36f264ff66ef6680b00090009000900090009000900090009000900090009000900090009000900090007d008d40b4047e5047ee36f', '862f01e3224f13d0fc7ff368037812d473e5302883660b4001e7806004e2ff700c612631028f102800e4402880620bd52c670bd608477c375c3771556735048d536008d808d40b480900047f264ff6680b000900005d400024cd0802b8f75600ffff3f00c0837b0060fb0a02' ),
			( 0x09167a0, '862f00e1e62f73e5224f2fd0e87ff36ee36817782dd4102883660b4001e708202e8980611c6001883a8d0288488d01e127d073e525d483660b4001e70820208d00e024d01ee53d9123d4121e0b40e3680820028d00e136910c3120d0e364111800e1131800e514180b4000e601e0187ee36f264ff66ef6680b0009000900090000e0187ee36f264ff66ef6680b0009000900090009000900090009000900090002e1c5af10280900090009000900090009000900', '862f01e7962f5369a62f01ea224f23d0e87ff3681778a02873e521d40b4083660820318993600488088f8061ff711c6118210a8f102805e207a0202801711c6405e33634018f4028a02816d873e514d4f36601e70b4817760820168d00e012d912d40b491ee50820018915955c3010da00e21296f364011f00e5621f241f231f0b4a00e601a001e000e0187f264ff66af669f6680b0009004c147204005d400024cd0802605c400020457b0040cd0802203e5000' )
		]

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
			ifile.close()
			print 'arfix-sh v1.2 Patched on image.'
			Fat_Inject( FileTarget, "EXEDSP", exeDSPFileName )
			return 1

		else:				#if there is difference on bytes give error
			print "Warning! This Firmware or script is CORRUPT!"
			print "OPERATION ABORTED!"
			ifile.close()
			return -1

	elif AutoPatcher( FileTarget, firmware ) == 0:
		print
		return 0
	print
	return 1

def force_remove( name ):
	if sys.platform=='win32':
		try:
			if os.path.exists(name):
				os.remove( name )
		except WindowsError:
			os.chmod( name, stat.S_IWRITE )
			os.remove( name )
	else:
		if os.path.exists(name):
			os.remove( name )

def DeleteDirectoryForced( deleted_dir ):
	for root, dirs, files in os.walk(deleted_dir, topdown=False):
		for name in files:
                        force_remove(root+os.path.sep+name)
		for name in dirs:
			os.rmdir(root+os.path.sep+name)
	os.rmdir(root)

def GetSquashFSToolsPath():
	toolspack = 'squashfs-tool-pack.tar.bz2'
	if not os.path.exists( toolspack ):
		print 'There is no '+toolspack+' detected on current directory.'
		address='http://downloads.sourceforge.net/project/samygo/SamyGO%20Tools/squashfs-tool-pack.tar.bz2'
		print 'Downloading '+toolspack+' from',address
		while 1:
			try:
				tst = urllib.urlopen( address )
				break
			except IOError:
				print address, ' - Error, retrying...'
				time.sleep(1)

		if tst.getcode() == 200:
			urllib.urlretrieve( address , toolspack )
			tst.close()
			print address, tst.getcode()
	else:
		print 'squashfs-tool-pack.tar.bz2 found at current directory.'
		print 'Extracting SquashFS 3.0 Tools.'
	import tarfile
	tar = tarfile.open( toolspack )
	tar.extractall()

	if sys.platform=='win32':
		return 'squashfs-tools\win32'

	elif sys.platform=='darwin':
		os.system('chmod +x squashfs-tools/macosx/*')
		return 'squashfs-tools/macosx'

	elif sys.platform=='linux2' and sys.maxint==2**31-1: #sys.arch='i386'
		os.system('chmod +x squashfs-tools/linux-x86/*')
		return 'squashfs-tools/linux-x86'

	elif sys.platform=='linux2' and sys.maxint==2**63-1: #sys.arch='x86_64'
		os.system('chmod +x squashfs-tools/linux-amd64/*')
		return 'squashfs-tools/linux-amd64'
	else:
		return ''

def Extract_Squash_exeDSP( SquashFSImage ):
	path = GetSquashFSToolsPath()
	if( path == '' ):
		print 'No SquashFS tools detected nor downloaded.'
		sys.exit()

	#Verify for v3.0 unsquashfs. Not strictly required...
	cmd = path + os.path.sep + 'unsquashfs -version'
	proc = subprocess.Popen( cmd, shell='true', stdout=subprocess.PIPE)
	proc.wait()
	a = proc.stdout.readline().find(' 1.0 ') #Not 3.0, squashFS 3.0 inc

	if( a > 0 ):
		cmd = path + os.path.sep +'unsquashfs -dest "' +os.path.dirname( SquashFSImage )+ os.path.sep + 'squashfs-root" "'+SquashFSImage+'"'
		print 'Extracting SquashFS Image'
		proc = subprocess.Popen( cmd, shell='true', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		proc.wait( )
		a = proc.stderr.read()

		if(len(a) == 0 or a.startswith('cygwin warning:')):
			#Create/move exeDSP file
			info = open(os.path.dirname( SquashFSImage )+os.path.sep+'info.txt').read().split(' ')
			exeDSPFileName=os.path.dirname( SquashFSImage )+os.path.sep+"exeDSP"+'-'+info[0]+'-'+info[1].strip();
			force_remove( exeDSPFileName )
			os.rename( os.path.dirname( SquashFSImage )+ os.path.sep +'squashfs-root' + os.path.sep + 'exeDSP', exeDSPFileName )
			print 'exeDSP file created at : ', exeDSPFileName
			print
			DeleteDirectoryForced( os.path.dirname( SquashFSImage )+ os.path.sep +'squashfs-root' )
			DeleteDirectoryForced( 'squashfs-tools')
			return exeDSPFileName
		else:
			print 'Error:',a
	else:
		print 'No SquashFS version 3.0 Tools detected.'
	return ''

def Inject_Squash_exeDSP( SquashFSImage, exeDSPFileName ):
	path = GetSquashFSToolsPath()
	if( path == '' ):
		print 'No SquashFS tools detected nor downloaded.'
		sys.exit()

	#Verify for verison if it's v3.0 or not
	cmd = path + os.path.sep +'mksquashfs -version'
	proc = subprocess.Popen( cmd, shell='true', stdout=subprocess.PIPE)
	proc.wait( )
	a = proc.stdout.readline().find(' 3.0 ')

	if( a > 0 ):
		cmd = path + os.path.sep + 'unsquashfs -dest "' +os.path.dirname( SquashFSImage )+ os.path.sep + 'squashfs-root" "' + SquashFSImage+'"'
		print 'Extracting SquashFS Image'
		proc = subprocess.Popen( cmd, shell='true', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		proc.wait( )
		a = proc.stderr.read()

		if(len(a) == 0 or a.startswith('cygwin warning:')):
                        force_remove( os.path.dirname( SquashFSImage )+os.path.sep+'squashfs-root'+os.path.sep+'exeDSP' )
			os.rename( exeDSPFileName, os.path.dirname( SquashFSImage )+os.path.sep+'squashfs-root'+os.path.sep+'exeDSP' )
			cmd = path + os.path.sep + 'mksquashfs "'+os.path.dirname( SquashFSImage )+os.path.sep+'squashfs-root" "'+SquashFSImage+'.repack" -b 65536 -le -all-root'
			print 'RePacking SquashFS Image'
			proc = subprocess.Popen( cmd, shell='true', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			proc.wait( )
			a = proc.stderr.read()
			os.rename( os.path.dirname( SquashFSImage )+os.path.sep+'squashfs-root'+os.path.sep+'exeDSP', exeDSPFileName ) #leave patched exeDSP at image directory
			DeleteDirectoryForced( os.path.dirname( SquashFSImage )+os.path.sep+'squashfs-root' )
			DeleteDirectoryForced( 'squashfs-tools' )
			force_remove( SquashFSImage )
			os.rename( SquashFSImage+'.repack', SquashFSImage )
			return True
		else:
			print 'Error:',a
	else:
		print 'No SquashFS version 3.0 Tools detected.'
	return False

def Fat_Extract( FatImage, filename ):
	print 'Extracting',filename,'from image'
	image=open( FatImage, 'r+b' )

	if image.read(4) == 'hsqs' :
		image.close()
		print 'SquashFS image type.'
		return Extract_Squash_exeDSP( FatImage )

	image.seek(54)
	if image.read(5) == ('FAT16' ) :
		print 'FAT16 image type.!'
	else:
		print "image file is not FAT16 nor SquasFS image. Please check if it's correctly decrypted"
		return ''

	image.seek(0)
	#First we needed to extract File from FAT image
	boot=image.read(50)
	BytesPerSector,    = struct.unpack( 'H', boot[0xb:0xb+2] )
	ReservedSector,    = struct.unpack( 'H', boot[0xe:0xe+2] )
	NumberOfFAT,       = struct.unpack( 'B', boot[0x10:0x10+1] )
	SectorsPerFAT,     = struct.unpack( 'H', boot[0x16:0x16+2] )
	MaxRootEntry,      = struct.unpack( 'H', boot[0x11:0x11+2] )
	SectorsPerCluster, = struct.unpack( 'B', boot[0xd:0xd+1] )
#	print "BytesPerSector   : 0x%X" % BytesPerSector
#	print "ReservedSector   : 0x%X" % ReservedSector
#	print "NumberOfFAT      : 0x%X" % NumberOfFAT
#	print "SectorsPerFAT    : 0x%X" % SectorsPerFAT
#	print "MaxRootEntry     : 0x%X" % MaxRootEntry
#	print "SectorsPerCluster: 0x%X" % SectorsPerCluster

	#the FAT track table goes all the way to HEAD 0 TRACK 0 SECTOR 18
	image.seek( (NumberOfFAT*SectorsPerFAT+ReservedSector)*BytesPerSector )
	FAT=image.read( SectorsPerFAT*BytesPerSector )
	FATofFile=''
	for i in range(0, len(FAT), 32):
	  if FAT[i:i+32].startswith(filename.upper()):
		 FATofFile = FAT[i:i+32]

	if FATofFile == '':
		print 'No',filename,'file found on image'
		return ''

	FileStartCluster, = struct.unpack( 'H', FATofFile[26:28] )
	FileSize,  = struct.unpack( 'I', FATofFile[28:32] )

	#FileStartSector = ReservedSectors(0x0e) + (NumofFAT(0x10) * Sectors2FAT(0x16)) + (MaxRootEntry(0x11) * 32 / BytesPerSector(0x0b)) + ((X - 2) * SectorsPerCluster(0x0d))
	FileSector= ReservedSector + NumberOfFAT * SectorsPerFAT + MaxRootEntry*32/BytesPerSector + ((FileStartCluster - 2) * SectorsPerCluster)

	FileStart = FileSector*BytesPerSector
	print 'FAT image analyzed - exeDSP location:',FileStart,' size:', FileSize
	image.seek( FileStart )
	FileInString = image.read( FileSize )

	#Create File file
	info = open(os.path.dirname( FatImage )+os.path.sep+'info.txt').read().split(' ')
	FilePath=os.path.dirname( FatImage )+os.path.sep+filename+'-'+info[0]+'-'+info[1].strip();
	FileFile=open( FilePath, 'w+b' )
	FileFile.write( FileInString )
	FileFile.close()
	print filename,'file created at : ', FilePath
	print
	return FilePath

def Fat_Inject( FatImage, filename, pathname ):
	print 'Injecting modified ',filename,' file to image'
	image=open( FatImage, 'r+b' )

	if image.read(4) == 'hsqs' :
		image.close()
		print 'SquashFS image type.'
		return Inject_Squash_exeDSP( FatImage, pathname )

	image.seek(54)
	if image.read(5) == ('FAT16' ) :
		print 'FAT16 image type.!'
	else:
		print "image file is not FAT16 nor SquasFS image. Please check if it's correctly decrypted"
		return False

	image.seek(0)
	#First we needed to extract File from FAT image
	boot=image.read(50)
	BytesPerSector,    = struct.unpack( 'H', boot[0xb:0xb+2] )
	ReservedSector,    = struct.unpack( 'H', boot[0xe:0xe+2] )
	NumberOfFAT,       = struct.unpack( 'B', boot[0x10:0x10+1] )
	SectorsPerFAT,     = struct.unpack( 'H', boot[0x16:0x16+2] )
	MaxRootEntry,      = struct.unpack( 'H', boot[0x11:0x11+2] )
	SectorsPerCluster, = struct.unpack( 'B', boot[0xd:0xd+1] )

	#the FAT track table goes all the way to HEAD 0 TRACK 0 SECTOR 18
	image.seek( (NumberOfFAT*SectorsPerFAT+ReservedSector)*BytesPerSector )
	FAT=image.read( SectorsPerFAT*BytesPerSector )

	FATofFile=''
	for i in range(0, len(FAT), 32):
	  if FAT[i:i+32].startswith(filename):
		 FATofFile = FAT[i:i+32]

	if FATofFile == '':
		print 'No',filename,'file found on image'
		return False

	FileStartCluster, = struct.unpack( 'H', FATofFile[26:28] )
	FileSize,  = struct.unpack( 'I', FATofFile[28:32] )

	#FileStartSector = ReservedSectors(0x0e) + (NumofFAT(0x10) * Sectors2FAT(0x16)) + (MaxRootEntry(0x11) * 32 / BytesPerSector(0x0b)) + ((X - 2) * SectorsPerCluster(0x0d))
	FileSector= ReservedSector + NumberOfFAT * SectorsPerFAT + MaxRootEntry*32/BytesPerSector + ((FileStartCluster - 2) * SectorsPerCluster)

	FileStart = FileSector*BytesPerSector
	print 'FAT image analyzed - File location:',FileStart,' size:', FileSize
	FileFile=open( pathname, 'rb' )
	FileInString = FileFile.read()
	FileFile.close()

	print 'Injection Size : ', len(FileInString)
	if len(FileInString) != FileSize:
		if FileSize/BytesPerSector == len(FileInString)/BytesPerSector:	#if sector count not changed, it's safe to inject
			print '''Warning: injection file has different size than original File. But doens't require new sector.'''
			for i in range(0, len(FAT), 32):
				if FAT[i:i+32].startswith(filename):
					image.seek( (NumberOfFAT*SectorsPerFAT+ReservedSector)*BytesPerSector + i + 28 )
					image.write( struct.pack('I', len(FileInString)) )
		else:
			print 'Injection requires new sector! Aborted.'
			return False
	image.seek( FileStart )
	image.write( FileInString )
	image.close()
	return True

def Patch_Wiselink_Player_Hack( exeDSPFileName ):
	print 'Patching Wiselink Player Hack'
	CheckItemEnableAdr = 0
	PressLeftRightKeyAdr = 0

	symtable = ReadELF( exeDSPFileName )
	#os.remove( exeDSPFileName )
	CheckItemEnable = [i for i in symtable if i[0].find( '_ZN16SsExeFactoryBase17t_CheckItemEnableEP17FactoryItemNode_t') >= 0][0]

	if len(CheckItemEnable) != 0 :
		CheckItemEnableAdr = CheckItemEnable[1] - 0x8000	# -0x8000 makes adress->Offset
		print 'SsExeFactoryBase::t_CheckItemEnable(FactoryItemNode_t *) Adress : 0x%X' % CheckItemEnableAdr
	else:
		print 'Error: Required adresses not found at exeDSP!'
		return 0
	 ####Wiselink Player Hack#####
	# 005AC6E0: CheckItemEnableAdr   #
	# +0x260 2401008A -> B7FFFF8A    #
	# -0x8000 for offset             #
	 #############################
	patch_address = [ CheckItemEnableAdr+0x0260,CheckItemEnableAdr+0x0261,CheckItemEnableAdr+0x0262 ]
	patch_check = ''
	patch_value = '\xB7\xFF\xFF'

	exeDSPFile = open( exeDSPFileName, 'r+b' )
	exeDSP = exeDSPFile.read()
	for i in patch_address:
		patch_check += exeDSP[i]

	if patch_check == "\x24\x01\x00":
		print "Wiselink Player Hack Compatibility Found."
		var = raw_input("Enable Wiselink Player Hack ( Y/n )? ")
		if var == 'n' or var == 'N':
			print "Wiselink Player Hack patch skipped."
			return 0
		##patch file code
		for i in range(0,len(patch_address)):
			exeDSPFile.seek( patch_address[i] )
			exeDSPFile.write( patch_value[i] )
		print 'Wiselink Player Hack patched to exeDSP'
		print
		return 1

	else:
		print "Wiselink Player Hack Compatibility NOT Found."
		print "Skipped Wiselink Player Hack."
		print
		return -1

def Patch_VideoAR_v1_Fix( exeDSPFileName ):
	print 'Patching VideoAR Fix v1'
	GetToolItemAdr = 0
	PressLeftRightKeyAdr = 0

	symtable = ReadELF( exeDSPFileName )
	#os.remove( exeDSPFileName )
	symtable = [i for i in symtable if i[0].find( '_ZNK23CToolMmbDisplaySizeItem') >= 0]
	GetToolItem = [i for i in symtable if i[0].find( 'GetToolItem') >= 0][0]
	PressLeftRightKey = [i for i in symtable if i[0].find( 'PressLeftRightKey') >= 0][0]

	if len(GetToolItem) * len(PressLeftRightKey) != 0 :
		GetToolItemAdr = GetToolItem[1] - 0x8000	# -0x8000 makes adress->Offset
		PressLeftRightKeyAdr = PressLeftRightKey[1] - 0x8000	# -0x8000 makes adress->Offset
		print 'CToolMmbDisplaySizeItem::GetToolItem() Adress : 0x%X' % GetToolItemAdr
		print 'CToolMmbDisplaySizeItem::PressLeftRightKey() Adress : 0x%X' % PressLeftRightKeyAdr
	else:
		print 'Error: Required adresses not found at exeDSP!'
		return 0
	 ########Video ARFix v1#######
	# 00FFAC00: GetToolItem:         #
	# +0x20 1 -> 4                   # 0x28 for CI+
	# +0x28 2 -> 1                   # 0x32 for CI+
	# 00FFAEF4: PressLeftRightKey    #
	# +0x24 1 -> 3                   # 0x38 for CI+
	# +0x3C 2 -> 4                   # 0x44 for CI+
	# +0x40 1 -> 3                   # 0x48 for CI+
	# -0x8000 for offset             #
	 #############################
	patch_address = [ GetToolItemAdr+0x20,	GetToolItemAdr+0x28,	PressLeftRightKeyAdr+0x30,	PressLeftRightKeyAdr+0x3C, PressLeftRightKeyAdr+0x40 ]
	patch_address_cip = [ GetToolItemAdr+0x28,	GetToolItemAdr+0x30,	PressLeftRightKeyAdr+0x38,	PressLeftRightKeyAdr+0x44, PressLeftRightKeyAdr+0x48 ]
	patch_check = ''
	patch_check_cip = ''
	patch_value = '\x04\x01\x03\x04\x03'

	exeDSPFile = open( exeDSPFileName, 'r+b' )
	exeDSP = exeDSPFile.read()
	for i in patch_address:
		patch_check += exeDSP[i]

	for i in patch_address_cip:
		patch_check_cip += exeDSP[i]

	if patch_check == "\x01\x02\x01\x02\x01":
		print "VideoAR Fix v1 for CI Compatibility Found."
		var = raw_input("Enable VideoAR Fix v1 ( Y/n )? ")
		if var == 'n' or var == 'N':
			print "VideoAR Fix v1 patch skipped."
			return 0
		##patch file code
		for i in range(0,len(patch_address)):
			exeDSPFile.seek( patch_address[i] )
			exeDSPFile.write( patch_value[i] )
		print 'VideoARFix v1 patched to exeDSP'
		print
		return 1

	elif patch_check_cip == "\x01\x02\x01\x02\x01":
		print "VideoAR Fix v1 for CI+ Compatibility Found."
		var = raw_input("Enable VideoAR Fix v1 ( Y/n )? ")
		if var == 'n' or var == 'N':
			print "VideoAR Fix v1 patch skipped."
			return 0
		##patch file code
		for i in range(0,len(patch_address_cip)):
			exeDSPFile.seek( patch_address_cip[i] )
			exeDSPFile.write( patch_value[i] )
		print 'VideoARFix v1 patched to exeDSP'
		print
		return 1

	else:
		print "VideoAR Fix v1 Compatibility NOT Found."
		print "Skipped VideoAR v1 Fix."
		print
		return -1

def Patch_Big_Subtitles( exeDSPFileName ):
	print 'Patching Big Subtitles'
	UpdateCaptionTextSizeAdr = 0
	InitCaptionAdr = 0

	symtable = ReadELF( exeDSPFileName )
	#os.remove( exeDSPFileName )
	symtable = [i for i in symtable if i[0].find( 'CMultimediaMovieInfo') >= 0]	#filters non required symbols for this hack
	UpdateCaptionTextSizeAdr = [i for i in symtable if i[0].find( '_ZN20CMultimediaMovieInfo21UpdateCaptionTextSizeEi') >= 0][0]
	InitCaptionAdr = [i for i in symtable if i[0].find( '_ZN20CMultimediaMovieInfo11InitCaptionEv') >= 0][0]

	if len(UpdateCaptionTextSizeAdr) * len(InitCaptionAdr) != 0 :
		UpdateCaptionTextSizeAdr = UpdateCaptionTextSizeAdr[1] - 0x8000	# -0x8000 makes adress->Offset
		InitCaptionAdr = InitCaptionAdr[1] - 0x8000	# -0x8000 makes adress->Offset
		print 'CMultimediaMovieInfo::UpdateCaptionTextSize() Adress : 0x%X' % UpdateCaptionTextSizeAdr
		print 'CMultimediaMovieInfo::InitCaption() Adress : 0x%X' % InitCaptionAdr
	else:
		print 'Error: Required adresses not found at exeDSP!'
		return 0
	 ######################Big Subtitles######################
	# 00DFDECC: _ZN20CMultimediaMovieInfo21UpdateCaptionTextSizeEi   #
	# +0x0C 18 -> 20                                                 # same for CI+
	# 00DFEC38: _ZN20CMultimediaMovieInfo11InitCaptionEv             #
	# +0x7C 18 -> 20                                                 # same for CI+
	# -0x8000 for offset                                             #
	 ###################Colorfull Subtitles###################
	# +0x88:00E598E0 LDR     R1, =0xFFF0F0F0 | BIN 38 10 9F E5       #
	# 00E598E0 + 38 + 8 = Color code area                            #
	# 00E59920  F0 F0 F0 FF   CI+ color                              #
	 #########################################################
	exeDSPFile = open( exeDSPFileName, 'r+b' )
	exeDSP = exeDSPFile.read()

	### Big Subtitle Patch
	patch_address = [ UpdateCaptionTextSizeAdr+0x0C,	InitCaptionAdr+0x7C ]
	patch_check = ''
	patch_value = '\x20\x20'

	patched=False

	for i in patch_address:
		patch_check += exeDSP[i]

	if patch_check == "\x18\x18":
		print "Big Subtitles Compatibility Found."
		var = raw_input("Enable Big Subtitles ( Y/n )? ")
		if var == 'n' or var == 'N':
			print "Big Subtitles patch skipped."
			print
		else:
			##patch file code
			for i in range(0,len(patch_address)):
				exeDSPFile.seek( patch_address[i] )
				exeDSPFile.write( patch_value[i] )
			print 'Big Subtitles patched to exeDSP'
			patched = True
	else:
		print "Big Subtitles Compatibility NOT Found."
		print "Big Subtitles patch skipped."
	print

	##Colorfull Subtitles Patch
	#Read value iteration 0x38 but needed to be sure.
	ColorKeyAdr, = struct.unpack( 'B', exeDSP[InitCaptionAdr + 0x88:InitCaptionAdr + 0x88 + 1] )
	ColorKeyAdr = InitCaptionAdr + 0x88 + ColorKeyAdr + 8
	Color, = struct.unpack( 'I', exeDSP[ColorKeyAdr:ColorKeyAdr+4] )

	print "Colorfull Subtitles ColorKey Adr 0x%X" % ColorKeyAdr + " Color: 0x%X" % Color
	if Color == 0xFFF0F0F0:
		print "Colorfull Subtitles Compatibility Found."
		var = raw_input("Want to Change Substitle Color ( y/N )? ")
		if var == 'y' or var == 'Y':
			while True:
				try:
					var = raw_input("Enter New Color Value as ARGB (default 0xFFF0F0F0) : 0x")
					if len(var) !=8:
						continue
					Color=int(var,16)
					exeDSPFile.seek( ColorKeyAdr )
					exeDSPFile.write( struct.pack( 'I',Color ) )
					print "Colorfull Subtitles patched to exeDSP."
					patched = True
					break
				except ValueError:
					print 'Error! Try Again.'
		else:
			print "Colorfull Subtitles patch skipped."

	print

	return patched

def AutoPatcher( FileTarget, firmware ):
	exeDSPFileName = Fat_Extract( FileTarget, "exeDSP" )
	if exeDSPFileName != '':
		a = Patch_VideoAR_v1_Fix( exeDSPFileName )
		b = Patch_Big_Subtitles( exeDSPFileName )
		c = 0
		if( firmware == 'T-CHL5DEUC' or firmware == 'T-CHE6AUSC'):
			c = Patch_Wiselink_Player_Hack( exeDSPFileName )
		if a or b or c:
			return Fat_Inject( FileTarget, "EXEDSP", exeDSPFileName )
	else:
		return False

def calculate_crc( decfile ):
	cfil = open( decfile, 'rb' )
	crc = binascii.crc32('')
	crc = binascii.crc32(cfil.read(),crc) & 0xffffffff
	print "Calculated CRC : 0x%X" % crc
	return crc

def AESprepare( salt, secret='', firmware='' ):
	try:
		from Crypto.Cipher import AES
	except ImportError:
		print 'Crypto package needed for decrypt AES encryption'
		print 'Please download and install corresponding version for your OS'
		print 'pyCrypto home www.pycrypto.org'
		print 'Download Windows Binaries at http://www.voidspace.org.uk/python/modules.shtml#pycrypto'
		print 'Win64 libraries could have bug. Use 32 bit python with 32 bit library instead.'
		sys.exit()

	if len( secret )==0:
		secret = "A435HX:d3e90afc-0f09-4054-9bac-350cc8dfc901-7cee72ea-15ae-45ce-b0f5-"
		if firmware.startswith( "T-GA" ):#T-GAS & T-GAP
			secret = "SHWJUH:85a045ae-2296-484c-b457-ede832fcfbe1-646390a3-105e-40aa-85f6-"
			secret += "da3086c70111"
		elif firmware.startswith("T-MST5"):#T-MST5
			secret = "SHWJUH:eceb2c14-db11-425e-9ebf-5f9607f0eb4b-3c38193e-751e-4719-8884-"
			secret += "9e76322c0cec"
		elif firmware.startswith("B-FIRB"):#tested with B-FIRBPEWWC 
			secret = "d6442d-7b46b2f4-0f11-4623-af63-8bb0a0d54c80-a22fbe2c-1bb5-49cc-b194-25c0f2b870f4"
		elif firmware.startswith("B-FIRU") or firmware.startswith("B-FIRH"):#bd-6* really ok for all FIR*???
			secret = "SHWJUH:db48ad51-c784-4f06-af57-1070a910c536-6a028bb5-e83e-45da-b326-a3a39ccba26c"
		elif firmware.startswith("T-MST4"):
			print "Error : Secret AES key cannot be calculated in this version of SamyGO Firmware Patcher."
			sys.exit()
		elif firmware.startswith("T-ECP"):
			secret = "3EF6067262CF0C678598BFF22169D1F1EA57C284"
		elif firmware.startswith("T-MST10P"):
			secret = "b4c136-fbc93576-b3e8-4035-bf4e-ba4cb4ada1ac-f0d81cc4-8301-4832-bd60-f331295743ba"
		elif firmware.startswith("T-MST") or firmware.startswith("T-MSU"):# 9P
			print "Error : Secret AES key cannot be calculated in this version of SamyGO Firmware Patcher."
			sys.exit()
		elif firmware.startswith("B-ECB"):
			secret = "SHWJUH:8fb684a9-84c1-46cf-aa81-977bce241542-6db4c136-8540-4ee4-8704-d9cd18590d11"
		elif firmware.startswith("T-VAL"):#C series AES key
			secret += "00001abc2010"
		elif firmware.startswith("T-TDT"):
			secret += "00002abc2010"
		elif firmware.startswith("T-MSX"):
			secret += "00004abc2010"
 		else: #B Series AES key
			secret +="611c4f8d4a71"

	print 'secret key : ', secret

	sha_secret = hashlib.sha1()
	sha_secret.update(secret)

	key = hashlib.md5()
	iv = hashlib.md5()

	if len( secret )==40:#E-Series binary pass
		key.update( binascii.unhexlify(secret) + salt )
		iv.update( key.digest() + binascii.unhexlify(secret) + salt )
	else:
		key.update( sha_secret.hexdigest() + salt )
		#key.hexdigest() - D_1
		iv.update( key.digest() + sha_secret.hexdigest() + salt )
		#iv.hexdigest() - D_2

	#openssl aes-128-cbc -d -in exe.img.sec -out exe.img -K e9e6627dc642a202bcf7bd6bdaaaa372 -iv b846d7ce24f89c6e160d455f8849c812
	cip_aes = AES.new( key.digest(), AES.MODE_CBC, iv.digest() )
	return cip_aes,AES.block_size

def AESdec( secfile, secret='', firmware='' ):
	filesec =  open( secfile,'rb')
	exeimgsec = filesec.read()
	signature_lenght=int(exeimgsec[-4:-1])
	# filesize - 4 byte to read signature size - 256 signature length - 8 salted__ - 8 salt
	decrypted_lenght = len(exeimgsec) - 4 - signature_lenght - 8 - 8

	if exeimgsec[0:8]!='Salted__':
		print "no salt at file"
		sys.exit()

	salt=exeimgsec[8:16]
	the_data = exeimgsec[16:decrypted_lenght+16]	#16 for 'Salted__' + salt

	cip_aes,tmp = AESprepare( salt, firmware=firmware )

	print 'Decrypting AES...'
	the_data = cip_aes.decrypt( the_data )

	encfilename = secfile[:secfile.rfind( '.' )]+'.enc'
	fileenc = open( encfilename,'wb' )
	fileenc.write( the_data[:-ord(the_data[-1])] ) #Removes the pad )
	fileenc.close()
	return encfilename

def AESenc( encfilename, secret='', firmware='' ):
	fileenc =  open( encfilename,'rb')
	salt = 'SamyGO__'

	cip_aes,AES_BLOCK_SIZE = AESprepare( salt, firmware=firmware )
	if AES_BLOCK_SIZE != 16:
		print "TV uses block size of 16 while this encryption using",AES_BLOCK_SIZE

	the_data = fileenc.read()
	pad = AES_BLOCK_SIZE - len(the_data) % AES_BLOCK_SIZE
	print 'Encrypting with AES...'
	the_data = cip_aes.encrypt( the_data+pad*chr(pad) )#Adding last 16 byte block for avoid AES cut
	print 'done'

	secfilename = encfilename[:encfilename.rfind( '.' )]+'.sec'
	filesec = open( secfilename,'wb' )
	filesec.write( 'Salted__' + salt )
	filesec.write( the_data )
	filesec.write( 256*'\x30')	#Empty Signature Area
	filesec.write( '256\n')
	filesec.close()
	return secfilename

def SamsungSerie( firmware=''):
	A=["T-RBYDEUC"]
	B=["T-CHL7DEUC","T-CHL5DEUC","T-CHE7AUSC","T-CHL7DAUC","T-CHU7DAUC","T-CHU7DEUC"]
	Bp=["T-CHLCIPDEUC","T-CHL5CIPDEUC","T-CHL6CIPDEUC","T-CHUCIPDEUC"]
	BDd=["B-FIRURDEUC","B-FIRHTBEUC","B-FIRHRDEUM","B-FIRHRDEUC"] #make also new type for BS...???
	BDe=["B-FIRBPEWWC"] #e-series bd-player
	C=["T-VALDEUC","T-VAL4DEUC","T-TDT5DAAC","T-MSX5DAAC","T-MSX5DEUC"]
	D=["T-GASDEUC","T-GAS6DEUC","T-GAPDEUC","T-GAP8DEUC","T-MST4DEUC", "T-MSU4DEUC"]
	Eb=["B-ECBHRDEUC"] #just preparation!!
	Ep=["T-ECPDEUC","T-ECPAKUC"]
	Ex=["T-MST10PDEUC"] #just preparation!!
	if( firmware in A ):
		return "A"
	elif firmware in Bp:
		return "B+"
	elif firmware.startswith("T-CH"):
		if os.path.isfile( firmware + os.path.sep + 'image' + os.path.sep + 'major_version' ):
			return "B+"
		else:
			return "B"
	elif firmware.startswith("T-VAL") or firmware.startswith("T-MSX") or firmware.startswith("T-TDT"): 
		return "C"
	elif firmware.startswith("B-ECB"):
		return "Eb"
	elif firmware.startswith("T-ECP"):
		return "Ep"
	elif firmware.startswith("T-MST10P"):
		return "Ex"
	elif firmware.startswith("T-GA") or firmware.startswith("T-MST4") or firmware.startswith("T-MSU4") or firmware.startswith("T-MST5"):
		return "D"
	elif firmware.startswith("B-FIRU") or firmware.startswith("B-FIRH"):
		return "BDd"
	elif firmware.startswith("B-FIRB"):
		return "BDe"

def DecryptAll( in_dir ):
	if not os.path.isdir( in_dir ):
		print "No valid directory with name of " + in_dir
		sys.exit()
	realdir = os.path.realpath( in_dir )
	#Reading firmware name for using as XOR decryption key
	key = open( realdir + os.path.sep + 'image' + os.path.sep + 'info.txt' , 'r' ).read().split(' ');
	print "Firmware: ",key[0],'v'+key[1]
	xorkey = ''
	fwdir = os.path.realpath( in_dir + os.path.sep + 'image' + os.path.sep )
	files = os.listdir( fwdir )
	files = [i for i in files if i.endswith('sec') or i.endswith('enc')]
	if SamsungSerie(key[0]) in ('B+','C','D','BDd','BDe','Eb','Ep','Ex'):
		encmode='CI+'
	elif SamsungSerie(key[0]) in ('B'):
		encmode='CI'
	if len(files) > 0:
		if( encmode == 'CI+'):
			print "AES Encrytped CI+ firmware detected."
		for f in files:
			print "Processing file", f
			if( encmode == 'CI+'):
				encfile = AESdec( fwdir + os.path.sep + f, firmware=key[0] )
			else:
				encfile = fwdir + os.path.sep + f
			print "Decrypting with ",
			decfile,md5digg,xorkey = xor( encfile,key[0] )
			CRC = calculate_crc(decfile)
			filevalid = open(realdir + os.path.sep +'image' + os.path.sep + 'validinfo.txt', 'r')
			ValidCRC = filevalid.read()
			filevalid.close()
			searchfor = f[:-4]+'_'
			CRCstart = ValidCRC.find( searchfor )+len(searchfor)
			ValidCRC = int(ValidCRC[CRCstart:CRCstart+8], 16)
			if CRC != ValidCRC:
				print 'Error on Decryption'
				sys.exit()
			else:
				print 'CRC Validation passed'
				print
				print

def Decryptor( in_dir ):
	if not os.path.isdir( in_dir ):
		print "No valid directory with name of " + in_dir
		sys.exit()
	encmode = 'none'
	#Reading firmware name for using as XOR decryption key
	realdir = os.path.realpath( in_dir )
	key = open( realdir + os.path.sep + 'image' + os.path.sep + 'info.txt' , 'r' ).read().split(' ');
	print "Firmware: ",key[0],'v'+key[1]
	xorkey = ''
	if os.path.isfile( realdir + os.path.sep + 'image' + os.path.sep + 'exe.img.sec' ):
		encmode = 'CI+'
		targetfile = realdir+os.path.sep+'image'+os.path.sep+'exe.img.sec'
		print "AES Encrytped CI+ firmware detected."
		print "Decrypting with AES..."
		encfile = AESdec( targetfile, firmware=key[0] )
		print
		print "Decrypting with ",
		decfile,md5digg,xorkey = xor( encfile )
		CRC = calculate_crc(decfile)
		filevalid = open(realdir + os.path.sep +'image' + os.path.sep + 'validinfo.txt', 'r')
		ValidCRC = filevalid.read()
		filevalid.close()
		CRCstart = ValidCRC.find('exe.img_')+8
		ValidCRC = int(ValidCRC[CRCstart:CRCstart+8], 16)

		if CRC != ValidCRC:
			print 'Error on Decryption'
			sys.exit()
		else:
			print 'CRC Validation passed'

	#add check that decryptor created .enc file or it was originaly shipped!!!!
	elif os.path.isfile( realdir+os.path.sep+'image'+os.path.sep+'exe.img.enc' ):
		encmode = 'CI'
		targetfile = realdir+os.path.sep+'image'+os.path.sep+'exe.img.enc'
		print "XOR Encrytped CI firmware detected."
		print "Decrypting with ",
		decfile,md5digg,xorkey = xor( targetfile )
		print
		return (xorkey,md5digg,decfile,encmode)

	elif os.path.isfile( realdir+os.path.sep+'image'+os.path.sep+'exe.img'):
		encmode = 'none'
		decfile = targetfile = realdir + os.path.sep+'image'+os.path.sep+'exe.img'
		print "Plain firmware detected."
		md5digg = hashlib.md5()
		df = open( decfile, 'rb' )
		md5digg.update( df.read() )
		md5digg = md5digg.hexdigest()
		df.close()
		print
		return (xorkey,md5digg,decfile,encmode)

	else:
		print 'No exe.img files found in directory of ' + in_dir
		sys.exit()

def EncryptAll( in_dir ):
	if not os.path.isdir( in_dir ):
		print "No valid directory with name of " + in_dir
		sys.exit()
	realdir = os.path.realpath( in_dir )
	#Reading firmware name for using as XOR decryption key
	key = open( realdir + os.path.sep + 'image' + os.path.sep + 'info.txt' , 'r' ).read().split(' ');
	print "Firmware: ",key[0],'v'+key[1]
	xorkey = ''
	fwdir = os.path.realpath( in_dir + os.path.sep + 'image' + os.path.sep )
	files = ['Image','exe.img','appext.img','rootfs.img','appdata.img','boot.img','onboot.bin','u-boot.bin','uboot_env.bin','onw.bin','fnw.bin','tlib.img','cmm.img','rocommon.img','emanual.img','rwcommon.img']
	files = [i for i in files if os.path.isfile(fwdir+os.path.sep+i)]
	if SamsungSerie(key[0]) in ('B+','C','D','BDd','BDe','Eb','Ep','Ex'):
		encmode='CI+'
	elif SamsungSerie(key[0]) in ('B'):
		encmode='CI'
	
	if SamsungSerie(key[0]) in ('BDd','BDe','Eb','Ep','Ex'):
		print 'Not supported in public release, too dangerous!!!'
		sys.exit()

	print "FileS",files
	if len(files) > 0:
		if encmode == 'CI+':
			print "AES Encrytped CI+ firmware detected."
		for f in files:
			print "Processing file:", f
			print "Encrypting with ",
			CRC = calculate_crc(fwdir + os.path.sep + f)
			validfile = open(realdir + os.path.sep+ 'image'+os.path.sep+'validinfo.txt', 'r+')
			searchfile= f+'_';
			loc = validfile.read().find(searchfile)+len(searchfile)
			validfile.seek( loc )
			print "Updating " + realdir +os.path.sep+ 'image'+os.path.sep+'validinfo.txt with new CRC.'
			validfile.write( "%08x" % CRC )
			validfile.close()
			decfile,md5digg,xorkey = xor( fwdir + os.path.sep + f,key[0] )
			print "Writen file",decfile	
			if encmode == 'CI+':
				encfile=AESenc( decfile, firmware=key[0] )
				print "Writen file",encfile
			print
			print


def Encryptor(in_dir, encmode=''):
	realdir = os.path.realpath( in_dir )
	key = open( realdir + os.path.sep + 'image' + os.path.sep + 'info.txt' , 'r' ).read().split(' ');
	firmware=key[0]
	if SamsungSerie(firmware) in ('C','D','BDd','BDe','Eb','Ep','Ex'):
		encmode='CI+'

	if SamsungSerie(key[0]) in ('BDd','BDe','Eb','Ep','Ex'):
		print 'Not supported in public release, too dangerous!!!'
		sys.exit()

	if encmode != 'none':
		print "Encrypting with ",
		decfile = realdir+os.path.sep+'image'+os.path.sep+'exe.img'
		encfile,tmp,tmp = xor( decfile, firmware )	#which means target file exe.img.enc now
		os.remove( decfile )
		if encmode == 'CI+':
			AESenc( encfile, firmware=firmware )	#now become targetfile exe.img.sec
			os.remove( encfile )

	print 'Operation successfully completed.'
	print 'Now you can flash your TV with ' + in_dir +' directory.'
	if encmode == 'CI+':
		print 'Please use "SamyGO RSA-Disabler Application" before flasing hacked firmware.'
		print 'DO NOT FORGET THE DISABLE WATCHDOG FROM SERVICE MENU FOR FLASHING'

#Main function, receives firmware's root directory
def SamyGO( in_dir ):
	pv  = pt = 0
	firmware,md5digg,decfile,encmode = Decryptor( in_dir )
	pv = patch( decfile, md5digg, firmware )
	if firmware == 'T-RBYDEUC':
	  pt = patch_TelnetRBYDEUC( decfile )
	else:
	  pt = patch_Telnet( decfile )

	if (pt or pv) and (pv != -1):	#if Telnet or Video patch applied
		crc = calculate_crc( decfile )
		realdir = os.path.realpath( in_dir )
		validfile = open(realdir + os.path.sep+ 'image'+os.path.sep+'validinfo.txt', 'r+')
		loc = validfile.read().find('exe.img_')
		validfile.seek( loc+8 )
		print "Updating " + realdir +os.path.sep+ 'image'+os.path.sep+'validinfo.txt with new CRC.'
		validfile.write( "%08x" % crc )
		validfile.close()
		print
		Encryptor( in_dir, encmode )

	else:
		print "No Change applied, Aborting..."

def ShowHelp():
	print "For use this script, you have to extract your firmware to a directory first!"
	print
	print "Than for patching a B series TV firmwares you can patch your FW by this command:"
	print "\tusage: python " + sys.argv[0] + " patch <path to extracted firmware directory>"
	print "\texample: python " + sys.argv[0] + " patch ./T-CHL7DEUC/"
	print
	print "Or you can decrypt/encrypt your A/B/C/D Series TV firmwares by this command"
	print "\tusage: python " + sys.argv[0] + " decrypt / encrypt <path to extracted firmware directory>"
	print "\texample: python " + sys.argv[0] + " decrypt ./T-VALDEUC/"
	print "\texample: python " + sys.argv[0] + " encrypt ./T-VALDEUC/"
	print
	print "\tusage: python " + sys.argv[0] + " decrypt_all / encrypt_all <path to extracted firmware directory>"




print "SamyGO Firmware Patcher v" + str(version) + " (c) 2010-2011 Erdem U. Altinyurt"
print
print '                   -=BIG FAT WARNING!=-'
print '            You can brick your TV with this tool!'
print 'Authors accept no responsibility about ANY DAMAGE on your devices!'
print '         project home: http://www.SamyGO.tv'
print
if len(sys.argv) != 3 or sys.argv[1] not in ('decrypt','encrypt', 'patch', 'decrypt_all','encrypt_all'):
	ShowHelp()
	sys.exit()
elif sys.argv[1].lower()=='patch':
	SamyGO( sys.argv[2] )
elif sys.argv[1].lower()=='decrypt':
	Decryptor( sys.argv[2] )
elif sys.argv[1].lower()=='encrypt':
	Encryptor( sys.argv[2] )
elif sys.argv[1].lower()=='decrypt_all':
	DecryptAll( sys.argv[2] )
elif sys.argv[1].lower()=='encrypt_all':
	EncryptAll( sys.argv[2] )
else:
	ShowHelp()
