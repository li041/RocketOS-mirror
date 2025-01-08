
../user/target/riscv64gc-unknown-none-elf/release/matrix:     file format elf64-littleriscv


Disassembly of section .text:

0000000000010000 <_start>:
   10000:	1101                	addi	sp,sp,-32
   10002:	ec06                	sd	ra,24(sp)
   10004:	e822                	sd	s0,16(sp)
   10006:	e426                	sd	s1,8(sp)
   10008:	e04a                	sd	s2,0(sp)
   1000a:	1000                	addi	s0,sp,32

000000000001000c <.Lpcrel_hi21>:
   1000c:	00007517          	auipc	a0,0x7
   10010:	ff450913          	addi	s2,a0,-12 # 17000 <_ZN8user_lib4HEAP17h79cac75b112c20f6E>
   10014:	4505                	li	a0,1
   10016:	00a934af          	amoadd.d	s1,a0,(s2)
   1001a:	00893503          	ld	a0,8(s2)
   1001e:	0230000f          	fence	r,rw
   10022:	00950a63          	beq	a0,s1,10036 <.Lpcrel_hi21+0x2a>
   10026:	0100000f          	fence	w,unknown
   1002a:	00893503          	ld	a0,8(s2)
   1002e:	0230000f          	fence	r,rw
   10032:	fe951ae3          	bne	a0,s1,10026 <.Lpcrel_hi21+0x1a>
   10036:	01090513          	addi	a0,s2,16

000000000001003a <.Lpcrel_hi22>:
   1003a:	00003597          	auipc	a1,0x3
   1003e:	fc658593          	addi	a1,a1,-58 # 13000 <_ZN8user_lib10HEAP_SPACE17h806b9f44b6d6d797E>
   10042:	6611                	lui	a2,0x4
   10044:	00001097          	auipc	ra,0x1
   10048:	cd2080e7          	jalr	-814(ra) # 10d16 <_ZN22buddy_system_allocator4Heap4init17h00d5b3cec7a683d4E>
   1004c:	0485                	addi	s1,s1,1
   1004e:	0310000f          	fence	rw,w
   10052:	00993423          	sd	s1,8(s2)
   10056:	00000097          	auipc	ra,0x0
   1005a:	010080e7          	jalr	16(ra) # 10066 <main>
   1005e:	00001097          	auipc	ra,0x1
   10062:	ca8080e7          	jalr	-856(ra) # 10d06 <_ZN8user_lib4exit17h972f8fe61fb14508E>

0000000000010066 <main>:
   10066:	a6010113          	addi	sp,sp,-1440
   1006a:	58113c23          	sd	ra,1432(sp)
   1006e:	58813823          	sd	s0,1424(sp)
   10072:	58913423          	sd	s1,1416(sp)
   10076:	59213023          	sd	s2,1408(sp)
   1007a:	57313c23          	sd	s3,1400(sp)
   1007e:	57413823          	sd	s4,1392(sp)
   10082:	57513423          	sd	s5,1384(sp)
   10086:	57613023          	sd	s6,1376(sp)
   1008a:	55713c23          	sd	s7,1368(sp)
   1008e:	55813823          	sd	s8,1360(sp)
   10092:	55913423          	sd	s9,1352(sp)
   10096:	55a13023          	sd	s10,1344(sp)
   1009a:	53b13c23          	sd	s11,1336(sp)
   1009e:	5a010413          	addi	s0,sp,1440
   100a2:	0dc00893          	li	a7,220
   100a6:	4501                	li	a0,0
   100a8:	4581                	li	a1,0
   100aa:	4601                	li	a2,0
   100ac:	00000073          	ecall
   100b0:	32050e63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   100b4:	0dc00893          	li	a7,220
   100b8:	4501                	li	a0,0
   100ba:	4581                	li	a1,0
   100bc:	4601                	li	a2,0
   100be:	00000073          	ecall
   100c2:	32050563          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   100c6:	0dc00893          	li	a7,220
   100ca:	4501                	li	a0,0
   100cc:	4581                	li	a1,0
   100ce:	4601                	li	a2,0
   100d0:	00000073          	ecall
   100d4:	30050c63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   100d8:	0dc00893          	li	a7,220
   100dc:	4501                	li	a0,0
   100de:	4581                	li	a1,0
   100e0:	4601                	li	a2,0
   100e2:	00000073          	ecall
   100e6:	30050363          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   100ea:	0dc00893          	li	a7,220
   100ee:	4501                	li	a0,0
   100f0:	4581                	li	a1,0
   100f2:	4601                	li	a2,0
   100f4:	00000073          	ecall
   100f8:	2e050a63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   100fc:	0dc00893          	li	a7,220
   10100:	4501                	li	a0,0
   10102:	4581                	li	a1,0
   10104:	4601                	li	a2,0
   10106:	00000073          	ecall
   1010a:	2e050163          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1010e:	0dc00893          	li	a7,220
   10112:	4501                	li	a0,0
   10114:	4581                	li	a1,0
   10116:	4601                	li	a2,0
   10118:	00000073          	ecall
   1011c:	2c050863          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10120:	0dc00893          	li	a7,220
   10124:	4501                	li	a0,0
   10126:	4581                	li	a1,0
   10128:	4601                	li	a2,0
   1012a:	00000073          	ecall
   1012e:	2a050f63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10132:	0dc00893          	li	a7,220
   10136:	4501                	li	a0,0
   10138:	4581                	li	a1,0
   1013a:	4601                	li	a2,0
   1013c:	00000073          	ecall
   10140:	2a050663          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10144:	0dc00893          	li	a7,220
   10148:	4501                	li	a0,0
   1014a:	4581                	li	a1,0
   1014c:	4601                	li	a2,0
   1014e:	00000073          	ecall
   10152:	28050d63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10156:	0dc00893          	li	a7,220
   1015a:	4501                	li	a0,0
   1015c:	4581                	li	a1,0
   1015e:	4601                	li	a2,0
   10160:	00000073          	ecall
   10164:	28050463          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10168:	0dc00893          	li	a7,220
   1016c:	4501                	li	a0,0
   1016e:	4581                	li	a1,0
   10170:	4601                	li	a2,0
   10172:	00000073          	ecall
   10176:	26050b63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1017a:	0dc00893          	li	a7,220
   1017e:	4501                	li	a0,0
   10180:	4581                	li	a1,0
   10182:	4601                	li	a2,0
   10184:	00000073          	ecall
   10188:	26050263          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1018c:	0dc00893          	li	a7,220
   10190:	4501                	li	a0,0
   10192:	4581                	li	a1,0
   10194:	4601                	li	a2,0
   10196:	00000073          	ecall
   1019a:	24050963          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1019e:	0dc00893          	li	a7,220
   101a2:	4501                	li	a0,0
   101a4:	4581                	li	a1,0
   101a6:	4601                	li	a2,0
   101a8:	00000073          	ecall
   101ac:	24050063          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   101b0:	0dc00893          	li	a7,220
   101b4:	4501                	li	a0,0
   101b6:	4581                	li	a1,0
   101b8:	4601                	li	a2,0
   101ba:	00000073          	ecall
   101be:	22050763          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   101c2:	0dc00893          	li	a7,220
   101c6:	4501                	li	a0,0
   101c8:	4581                	li	a1,0
   101ca:	4601                	li	a2,0
   101cc:	00000073          	ecall
   101d0:	20050e63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   101d4:	0dc00893          	li	a7,220
   101d8:	4501                	li	a0,0
   101da:	4581                	li	a1,0
   101dc:	4601                	li	a2,0
   101de:	00000073          	ecall
   101e2:	20050563          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   101e6:	0dc00893          	li	a7,220
   101ea:	4501                	li	a0,0
   101ec:	4581                	li	a1,0
   101ee:	4601                	li	a2,0
   101f0:	00000073          	ecall
   101f4:	1e050c63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   101f8:	0dc00893          	li	a7,220
   101fc:	4501                	li	a0,0
   101fe:	4581                	li	a1,0
   10200:	4601                	li	a2,0
   10202:	00000073          	ecall
   10206:	1e050363          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1020a:	0dc00893          	li	a7,220
   1020e:	4501                	li	a0,0
   10210:	4581                	li	a1,0
   10212:	4601                	li	a2,0
   10214:	00000073          	ecall
   10218:	1c050a63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1021c:	0dc00893          	li	a7,220
   10220:	4501                	li	a0,0
   10222:	4581                	li	a1,0
   10224:	4601                	li	a2,0
   10226:	00000073          	ecall
   1022a:	1c050163          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1022e:	0dc00893          	li	a7,220
   10232:	4501                	li	a0,0
   10234:	4581                	li	a1,0
   10236:	4601                	li	a2,0
   10238:	00000073          	ecall
   1023c:	1a050863          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10240:	0dc00893          	li	a7,220
   10244:	4501                	li	a0,0
   10246:	4581                	li	a1,0
   10248:	4601                	li	a2,0
   1024a:	00000073          	ecall
   1024e:	18050f63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10252:	0dc00893          	li	a7,220
   10256:	4501                	li	a0,0
   10258:	4581                	li	a1,0
   1025a:	4601                	li	a2,0
   1025c:	00000073          	ecall
   10260:	18050663          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10264:	0dc00893          	li	a7,220
   10268:	4501                	li	a0,0
   1026a:	4581                	li	a1,0
   1026c:	4601                	li	a2,0
   1026e:	00000073          	ecall
   10272:	16050d63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10276:	0dc00893          	li	a7,220
   1027a:	4501                	li	a0,0
   1027c:	4581                	li	a1,0
   1027e:	4601                	li	a2,0
   10280:	00000073          	ecall
   10284:	16050463          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   10288:	0dc00893          	li	a7,220
   1028c:	4501                	li	a0,0
   1028e:	4581                	li	a1,0
   10290:	4601                	li	a2,0
   10292:	00000073          	ecall
   10296:	14050b63          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   1029a:	0dc00893          	li	a7,220
   1029e:	4501                	li	a0,0
   102a0:	4581                	li	a1,0
   102a2:	4601                	li	a2,0
   102a4:	00000073          	ecall
   102a8:	14050263          	beqz	a0,103ec <.Lpcrel_hi5+0x12>
   102ac:	0dc00893          	li	a7,220
   102b0:	4501                	li	a0,0
   102b2:	4581                	li	a1,0
   102b4:	4601                	li	a2,0
   102b6:	00000073          	ecall
   102ba:	12050963          	beqz	a0,103ec <.Lpcrel_hi5+0x12>

00000000000102be <.Lpcrel_hi0>:
   102be:	00002517          	auipc	a0,0x2
   102c2:	df250513          	addi	a0,a0,-526 # 120b0 <.Lanon.fad58de7366495db4650cfefac2fcd61.8>
   102c6:	daa43423          	sd	a0,-600(s0)
   102ca:	4505                	li	a0,1
   102cc:	daa43823          	sd	a0,-592(s0)
   102d0:	dc043423          	sd	zero,-568(s0)
   102d4:	4521                	li	a0,8
   102d6:	daa43c23          	sd	a0,-584(s0)
   102da:	dc043023          	sd	zero,-576(s0)
   102de:	da840513          	addi	a0,s0,-600
   102e2:	00001097          	auipc	ra,0x1
   102e6:	8c0080e7          	jalr	-1856(ra) # 10ba2 <_ZN8user_lib7console5print17h77e18570bd382f8eE>
   102ea:	4681                	li	a3,0
   102ec:	c0042c23          	sw	zero,-1000(s0)
   102f0:	4779                	li	a4,30
   102f2:	57f9                	li	a5,-2
   102f4:	a021                	j	102fc <.Lpcrel_hi0+0x3e>
   102f6:	0685                	addi	a3,a3,1
   102f8:	0c054d63          	bltz	a0,103d2 <.Lpcrel_hi4>
   102fc:	557d                	li	a0,-1
   102fe:	c1840593          	addi	a1,s0,-1000
   10302:	10400893          	li	a7,260
   10306:	02e68963          	beq	a3,a4,10338 <.Lpcrel_hi0+0x7a>
   1030a:	4601                	li	a2,0
   1030c:	00000073          	ecall
   10310:	fef513e3          	bne	a0,a5,102f6 <.Lpcrel_hi0+0x38>
   10314:	07c00893          	li	a7,124
   10318:	4501                	li	a0,0
   1031a:	4581                	li	a1,0
   1031c:	4601                	li	a2,0
   1031e:	00000073          	ecall
   10322:	557d                	li	a0,-1
   10324:	c1840593          	addi	a1,s0,-1000
   10328:	10400893          	li	a7,260
   1032c:	4601                	li	a2,0
   1032e:	00000073          	ecall
   10332:	fef501e3          	beq	a0,a5,10314 <.Lpcrel_hi0+0x56>
   10336:	b7c1                	j	102f6 <.Lpcrel_hi0+0x38>
   10338:	56f9                	li	a3,-2
   1033a:	4601                	li	a2,0
   1033c:	00000073          	ecall
   10340:	02d51363          	bne	a0,a3,10366 <.Lpcrel_hi0+0xa8>
   10344:	07c00893          	li	a7,124
   10348:	4501                	li	a0,0
   1034a:	4581                	li	a1,0
   1034c:	4601                	li	a2,0
   1034e:	00000073          	ecall
   10352:	557d                	li	a0,-1
   10354:	c1840593          	addi	a1,s0,-1000
   10358:	10400893          	li	a7,260
   1035c:	4601                	li	a2,0
   1035e:	00000073          	ecall
   10362:	fed501e3          	beq	a0,a3,10344 <.Lpcrel_hi0+0x86>
   10366:	6a055d63          	bgez	a0,10a20 <.Lpcrel_hi1>

000000000001036a <.Lpcrel_hi3>:
   1036a:	00002517          	auipc	a0,0x2
   1036e:	d6650513          	addi	a0,a0,-666 # 120d0 <.Lanon.fad58de7366495db4650cfefac2fcd61.10>
   10372:	daa43423          	sd	a0,-600(s0)
   10376:	4505                	li	a0,1
   10378:	daa43823          	sd	a0,-592(s0)
   1037c:	dc043423          	sd	zero,-568(s0)
   10380:	4521                	li	a0,8
   10382:	daa43c23          	sd	a0,-584(s0)
   10386:	dc043023          	sd	zero,-576(s0)
   1038a:	da840513          	addi	a0,s0,-600
   1038e:	00001097          	auipc	ra,0x1
   10392:	814080e7          	jalr	-2028(ra) # 10ba2 <_ZN8user_lib7console5print17h77e18570bd382f8eE>
   10396:	4501                	li	a0,0
   10398:	59813083          	ld	ra,1432(sp)
   1039c:	59013403          	ld	s0,1424(sp)
   103a0:	58813483          	ld	s1,1416(sp)
   103a4:	58013903          	ld	s2,1408(sp)
   103a8:	57813983          	ld	s3,1400(sp)
   103ac:	57013a03          	ld	s4,1392(sp)
   103b0:	56813a83          	ld	s5,1384(sp)
   103b4:	56013b03          	ld	s6,1376(sp)
   103b8:	55813b83          	ld	s7,1368(sp)
   103bc:	55013c03          	ld	s8,1360(sp)
   103c0:	54813c83          	ld	s9,1352(sp)
   103c4:	54013d03          	ld	s10,1344(sp)
   103c8:	53813d83          	ld	s11,1336(sp)
   103cc:	5a010113          	addi	sp,sp,1440
   103d0:	8082                	ret

00000000000103d2 <.Lpcrel_hi4>:
   103d2:	00002517          	auipc	a0,0x2
   103d6:	d5650513          	addi	a0,a0,-682 # 12128 <.Lanon.fad58de7366495db4650cfefac2fcd61.13>

00000000000103da <.Lpcrel_hi5>:
   103da:	00002597          	auipc	a1,0x2
   103de:	d5e58613          	addi	a2,a1,-674 # 12138 <.Lanon.fad58de7366495db4650cfefac2fcd61.14>
   103e2:	45b1                	li	a1,12
   103e4:	00001097          	auipc	ra,0x1
   103e8:	aca080e7          	jalr	-1334(ra) # 10eae <_ZN4core9panicking5panic17h026dc666659124b0E>
   103ec:	0a900893          	li	a7,169

00000000000103f0 <.Lpcrel_hi6>:
   103f0:	00002517          	auipc	a0,0x2
   103f4:	c6853683          	ld	a3,-920(a0) # 12058 <$d>
   103f8:	4501                	li	a0,0
   103fa:	4581                	li	a1,0
   103fc:	4601                	li	a2,0
   103fe:	00000073          	ecall
   10402:	2501                	sext.w	a0,a0
   10404:	02a50533          	mul	a0,a0,a0
   10408:	02d535b3          	mulhu	a1,a0,a3
   1040c:	819d                	srli	a1,a1,0x7
   1040e:	3e800613          	li	a2,1000
   10412:	02c585b3          	mul	a1,a1,a2
   10416:	8d0d                	sub	a0,a0,a1
   10418:	45a9                	li	a1,10
   1041a:	02b50533          	mul	a0,a0,a1
   1041e:	a8a43023          	sd	a0,-1408(s0)
   10422:	b3440513          	addi	a0,s0,-1228
   10426:	0e400613          	li	a2,228
   1042a:	4581                	li	a1,0
   1042c:	00001097          	auipc	ra,0x1
   10430:	624080e7          	jalr	1572(ra) # 11a50 <memset>
   10434:	cc440513          	addi	a0,s0,-828
   10438:	0e400613          	li	a2,228
   1043c:	4581                	li	a1,0
   1043e:	00001097          	auipc	ra,0x1
   10442:	612080e7          	jalr	1554(ra) # 11a50 <memset>
   10446:	da840513          	addi	a0,s0,-600
   1044a:	19000613          	li	a2,400
   1044e:	4581                	li	a1,0
   10450:	00001097          	auipc	ra,0x1
   10454:	600080e7          	jalr	1536(ra) # 11a50 <memset>
   10458:	4505                	li	a0,1
   1045a:	a8a42423          	sw	a0,-1400(s0)
   1045e:	c0a42c23          	sw	a0,-1000(s0)
   10462:	a8a42623          	sw	a0,-1396(s0)
   10466:	c0a42e23          	sw	a0,-996(s0)
   1046a:	a8a42823          	sw	a0,-1392(s0)
   1046e:	c2a42023          	sw	a0,-992(s0)
   10472:	a8a42a23          	sw	a0,-1388(s0)
   10476:	c2a42223          	sw	a0,-988(s0)
   1047a:	a8a42c23          	sw	a0,-1384(s0)
   1047e:	c2a42423          	sw	a0,-984(s0)
   10482:	a8a42e23          	sw	a0,-1380(s0)
   10486:	c2a42623          	sw	a0,-980(s0)
   1048a:	aaa42023          	sw	a0,-1376(s0)
   1048e:	c2a42823          	sw	a0,-976(s0)
   10492:	aaa42223          	sw	a0,-1372(s0)
   10496:	c2a42a23          	sw	a0,-972(s0)
   1049a:	aaa42423          	sw	a0,-1368(s0)
   1049e:	c2a42c23          	sw	a0,-968(s0)
   104a2:	aaa42623          	sw	a0,-1364(s0)
   104a6:	c2a42e23          	sw	a0,-964(s0)
   104aa:	aaa42823          	sw	a0,-1360(s0)
   104ae:	c4a42023          	sw	a0,-960(s0)
   104b2:	aaa42a23          	sw	a0,-1356(s0)
   104b6:	c4a42223          	sw	a0,-956(s0)
   104ba:	aaa42c23          	sw	a0,-1352(s0)
   104be:	c4a42423          	sw	a0,-952(s0)
   104c2:	aaa42e23          	sw	a0,-1348(s0)
   104c6:	c4a42623          	sw	a0,-948(s0)
   104ca:	aca42023          	sw	a0,-1344(s0)
   104ce:	c4a42823          	sw	a0,-944(s0)
   104d2:	aca42223          	sw	a0,-1340(s0)
   104d6:	c4a42a23          	sw	a0,-940(s0)
   104da:	aca42423          	sw	a0,-1336(s0)
   104de:	c4a42c23          	sw	a0,-936(s0)
   104e2:	aca42623          	sw	a0,-1332(s0)
   104e6:	c4a42e23          	sw	a0,-932(s0)
   104ea:	aca42823          	sw	a0,-1328(s0)
   104ee:	c6a42023          	sw	a0,-928(s0)
   104f2:	aca42a23          	sw	a0,-1324(s0)
   104f6:	c6a42223          	sw	a0,-924(s0)
   104fa:	aca42c23          	sw	a0,-1320(s0)
   104fe:	c6a42423          	sw	a0,-920(s0)
   10502:	aca42e23          	sw	a0,-1316(s0)
   10506:	c6a42623          	sw	a0,-916(s0)
   1050a:	aea42023          	sw	a0,-1312(s0)
   1050e:	c6a42823          	sw	a0,-912(s0)
   10512:	aea42223          	sw	a0,-1308(s0)
   10516:	c6a42a23          	sw	a0,-908(s0)
   1051a:	aea42423          	sw	a0,-1304(s0)
   1051e:	c6a42c23          	sw	a0,-904(s0)
   10522:	aea42623          	sw	a0,-1300(s0)
   10526:	c6a42e23          	sw	a0,-900(s0)
   1052a:	aea42823          	sw	a0,-1296(s0)
   1052e:	c8a42023          	sw	a0,-896(s0)
   10532:	aea42a23          	sw	a0,-1292(s0)
   10536:	c8a42223          	sw	a0,-892(s0)
   1053a:	aea42c23          	sw	a0,-1288(s0)
   1053e:	c8a42423          	sw	a0,-888(s0)
   10542:	aea42e23          	sw	a0,-1284(s0)
   10546:	c8a42623          	sw	a0,-884(s0)
   1054a:	b0a42023          	sw	a0,-1280(s0)
   1054e:	c8a42823          	sw	a0,-880(s0)
   10552:	b0a42223          	sw	a0,-1276(s0)
   10556:	c8a42a23          	sw	a0,-876(s0)
   1055a:	b0a42423          	sw	a0,-1272(s0)
   1055e:	c8a42c23          	sw	a0,-872(s0)
   10562:	b0a42623          	sw	a0,-1268(s0)
   10566:	c8a42e23          	sw	a0,-868(s0)
   1056a:	b0a42823          	sw	a0,-1264(s0)
   1056e:	caa42023          	sw	a0,-864(s0)
   10572:	b0a42a23          	sw	a0,-1260(s0)
   10576:	caa42223          	sw	a0,-860(s0)
   1057a:	b0a42c23          	sw	a0,-1256(s0)
   1057e:	caa42423          	sw	a0,-856(s0)
   10582:	b0a42e23          	sw	a0,-1252(s0)
   10586:	caa42623          	sw	a0,-852(s0)
   1058a:	b2a42023          	sw	a0,-1248(s0)
   1058e:	caa42823          	sw	a0,-848(s0)
   10592:	b2a42223          	sw	a0,-1244(s0)
   10596:	caa42a23          	sw	a0,-844(s0)
   1059a:	b2a42423          	sw	a0,-1240(s0)
   1059e:	caa42c23          	sw	a0,-840(s0)
   105a2:	b2a42623          	sw	a0,-1236(s0)
   105a6:	caa42e23          	sw	a0,-836(s0)
   105aa:	b2a42823          	sw	a0,-1232(s0)
   105ae:	cca42023          	sw	a0,-832(s0)
   105b2:	b2a42a23          	sw	a0,-1228(s0)
   105b6:	cca42223          	sw	a0,-828(s0)
   105ba:	b2a42c23          	sw	a0,-1224(s0)
   105be:	cca42423          	sw	a0,-824(s0)
   105c2:	b2a42e23          	sw	a0,-1220(s0)
   105c6:	cca42623          	sw	a0,-820(s0)
   105ca:	b4a42023          	sw	a0,-1216(s0)
   105ce:	cca42823          	sw	a0,-816(s0)
   105d2:	b4a42223          	sw	a0,-1212(s0)
   105d6:	cca42a23          	sw	a0,-812(s0)
   105da:	b4a42423          	sw	a0,-1208(s0)
   105de:	cca42c23          	sw	a0,-808(s0)
   105e2:	b4a42623          	sw	a0,-1204(s0)
   105e6:	cca42e23          	sw	a0,-804(s0)
   105ea:	b4a42823          	sw	a0,-1200(s0)
   105ee:	cea42023          	sw	a0,-800(s0)
   105f2:	b4a42a23          	sw	a0,-1196(s0)
   105f6:	cea42223          	sw	a0,-796(s0)
   105fa:	b4a42c23          	sw	a0,-1192(s0)
   105fe:	cea42423          	sw	a0,-792(s0)
   10602:	b4a42e23          	sw	a0,-1188(s0)
   10606:	cea42623          	sw	a0,-788(s0)
   1060a:	b6a42023          	sw	a0,-1184(s0)
   1060e:	cea42823          	sw	a0,-784(s0)
   10612:	b6a42223          	sw	a0,-1180(s0)
   10616:	cea42a23          	sw	a0,-780(s0)
   1061a:	b6a42423          	sw	a0,-1176(s0)
   1061e:	cea42c23          	sw	a0,-776(s0)
   10622:	b6a42623          	sw	a0,-1172(s0)
   10626:	cea42e23          	sw	a0,-772(s0)
   1062a:	b6a42823          	sw	a0,-1168(s0)
   1062e:	d0a42023          	sw	a0,-768(s0)
   10632:	b6a42a23          	sw	a0,-1164(s0)
   10636:	d0a42223          	sw	a0,-764(s0)
   1063a:	b6a42c23          	sw	a0,-1160(s0)
   1063e:	d0a42423          	sw	a0,-760(s0)
   10642:	b6a42e23          	sw	a0,-1156(s0)
   10646:	d0a42623          	sw	a0,-756(s0)
   1064a:	b8a42023          	sw	a0,-1152(s0)
   1064e:	d0a42823          	sw	a0,-752(s0)
   10652:	b8a42223          	sw	a0,-1148(s0)
   10656:	d0a42a23          	sw	a0,-748(s0)
   1065a:	b8a42423          	sw	a0,-1144(s0)
   1065e:	d0a42c23          	sw	a0,-744(s0)
   10662:	b8a42623          	sw	a0,-1140(s0)
   10666:	d0a42e23          	sw	a0,-740(s0)
   1066a:	b8a42823          	sw	a0,-1136(s0)
   1066e:	d2a42023          	sw	a0,-736(s0)
   10672:	b8a42a23          	sw	a0,-1132(s0)
   10676:	d2a42223          	sw	a0,-732(s0)
   1067a:	b8a42c23          	sw	a0,-1128(s0)
   1067e:	d2a42423          	sw	a0,-728(s0)
   10682:	b8a42e23          	sw	a0,-1124(s0)
   10686:	d2a42623          	sw	a0,-724(s0)
   1068a:	baa42023          	sw	a0,-1120(s0)
   1068e:	d2a42823          	sw	a0,-720(s0)
   10692:	baa42223          	sw	a0,-1116(s0)
   10696:	d2a42a23          	sw	a0,-716(s0)
   1069a:	baa42423          	sw	a0,-1112(s0)
   1069e:	d2a42c23          	sw	a0,-712(s0)
   106a2:	baa42623          	sw	a0,-1108(s0)
   106a6:	d2a42e23          	sw	a0,-708(s0)
   106aa:	baa42823          	sw	a0,-1104(s0)
   106ae:	d4a42023          	sw	a0,-704(s0)
   106b2:	baa42a23          	sw	a0,-1100(s0)
   106b6:	d4a42223          	sw	a0,-700(s0)
   106ba:	baa42c23          	sw	a0,-1096(s0)
   106be:	d4a42423          	sw	a0,-696(s0)
   106c2:	baa42e23          	sw	a0,-1092(s0)
   106c6:	d4a42623          	sw	a0,-692(s0)
   106ca:	bca42023          	sw	a0,-1088(s0)
   106ce:	d4a42823          	sw	a0,-688(s0)
   106d2:	bca42223          	sw	a0,-1084(s0)
   106d6:	d4a42a23          	sw	a0,-684(s0)
   106da:	bca42423          	sw	a0,-1080(s0)
   106de:	d4a42c23          	sw	a0,-680(s0)
   106e2:	bca42623          	sw	a0,-1076(s0)
   106e6:	d4a42e23          	sw	a0,-676(s0)
   106ea:	bca42823          	sw	a0,-1072(s0)
   106ee:	d6a42023          	sw	a0,-672(s0)
   106f2:	bca42a23          	sw	a0,-1068(s0)
   106f6:	d6a42223          	sw	a0,-668(s0)
   106fa:	bca42c23          	sw	a0,-1064(s0)
   106fe:	d6a42423          	sw	a0,-664(s0)
   10702:	bca42e23          	sw	a0,-1060(s0)
   10706:	d6a42623          	sw	a0,-660(s0)
   1070a:	bea42023          	sw	a0,-1056(s0)
   1070e:	d6a42823          	sw	a0,-656(s0)
   10712:	bea42223          	sw	a0,-1052(s0)
   10716:	d6a42a23          	sw	a0,-652(s0)
   1071a:	bea42423          	sw	a0,-1048(s0)
   1071e:	d6a42c23          	sw	a0,-648(s0)
   10722:	bea42623          	sw	a0,-1044(s0)
   10726:	d6a42e23          	sw	a0,-644(s0)
   1072a:	bea42823          	sw	a0,-1040(s0)
   1072e:	d8a42023          	sw	a0,-640(s0)
   10732:	bea42a23          	sw	a0,-1036(s0)
   10736:	d8a42223          	sw	a0,-636(s0)
   1073a:	bea42c23          	sw	a0,-1032(s0)
   1073e:	d8a42423          	sw	a0,-632(s0)
   10742:	bea42e23          	sw	a0,-1028(s0)
   10746:	d8a42623          	sw	a0,-628(s0)
   1074a:	c0a42023          	sw	a0,-1024(s0)
   1074e:	d8a42823          	sw	a0,-624(s0)
   10752:	c0a42223          	sw	a0,-1020(s0)
   10756:	d8a42a23          	sw	a0,-620(s0)
   1075a:	c0a42423          	sw	a0,-1016(s0)
   1075e:	d8a42c23          	sw	a0,-616(s0)
   10762:	c0a42623          	sw	a0,-1012(s0)
   10766:	d8a42e23          	sw	a0,-612(s0)
   1076a:	c0a42823          	sw	a0,-1008(s0)
   1076e:	daa42023          	sw	a0,-608(s0)
   10772:	c0a42a23          	sw	a0,-1004(s0)
   10776:	daa42223          	sw	a0,-604(s0)
   1077a:	07c00893          	li	a7,124
   1077e:	4501                	li	a0,0
   10780:	4581                	li	a1,0
   10782:	4601                	li	a2,0
   10784:	00000073          	ecall
   10788:	0ac00893          	li	a7,172
   1078c:	4501                	li	a0,0
   1078e:	4581                	li	a1,0
   10790:	4601                	li	a2,0
   10792:	00000073          	ecall
   10796:	f8a43423          	sd	a0,-120(s0)
   1079a:	f8840513          	addi	a0,s0,-120
   1079e:	f2a43c23          	sd	a0,-200(s0)

00000000000107a2 <.Lpcrel_hi7>:
   107a2:	00001517          	auipc	a0,0x1
   107a6:	17050593          	addi	a1,a0,368 # 11912 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$i64$GT$3fmt17hc54d1578b1a353a6E>
   107aa:	f4b43023          	sd	a1,-192(s0)
   107ae:	a8040513          	addi	a0,s0,-1408
   107b2:	f4a43423          	sd	a0,-184(s0)
   107b6:	a6b43423          	sd	a1,-1432(s0)
   107ba:	f4b43823          	sd	a1,-176(s0)

00000000000107be <.Lpcrel_hi8>:
   107be:	00002517          	auipc	a0,0x2
   107c2:	86250513          	addi	a0,a0,-1950 # 12020 <.Lanon.fad58de7366495db4650cfefac2fcd61.3>
   107c6:	f4a43c23          	sd	a0,-168(s0)
   107ca:	450d                	li	a0,3
   107cc:	f6a43023          	sd	a0,-160(s0)
   107d0:	f6043c23          	sd	zero,-136(s0)
   107d4:	f3840513          	addi	a0,s0,-200
   107d8:	f6a43423          	sd	a0,-152(s0)
   107dc:	4509                	li	a0,2
   107de:	f6a43823          	sd	a0,-144(s0)
   107e2:	f5840513          	addi	a0,s0,-168
   107e6:	00000097          	auipc	ra,0x0
   107ea:	3bc080e7          	jalr	956(ra) # 10ba2 <_ZN8user_lib7console5print17h77e18570bd382f8eE>
   107ee:	a8043503          	ld	a0,-1408(s0)
   107f2:	a6a43823          	sd	a0,-1424(s0)
   107f6:	1ca05763          	blez	a0,109c4 <.Lpcrel_hi8+0x206>
   107fa:	4581                	li	a1,0
   107fc:	ce040a93          	addi	s5,s0,-800
   10800:	a8840a13          	addi	s4,s0,-1400
   10804:	68c8c537          	lui	a0,0x68c8c
   10808:	4ad50b1b          	addiw	s6,a0,1197
   1080c:	6509                	lui	a0,0x2
   1080e:	71750b93          	addi	s7,a0,1815 # 2717 <$d+0x26b9>
   10812:	a6b43c23          	sd	a1,-1416(s0)
   10816:	4881                	li	a7,0
   10818:	4505                	li	a0,1
   1081a:	da840293          	addi	t0,s0,-600
   1081e:	02800593          	li	a1,40
   10822:	02b88733          	mul	a4,a7,a1
   10826:	00ea07b3          	add	a5,s4,a4
   1082a:	0007a303          	lw	t1,0(a5)
   1082e:	0047a383          	lw	t2,4(a5)
   10832:	0087ae03          	lw	t3,8(a5)
   10836:	00c7ae83          	lw	t4,12(a5)
   1083a:	0107af03          	lw	t5,16(a5)
   1083e:	0147af83          	lw	t6,20(a5)
   10842:	0187a083          	lw	ra,24(a5)
   10846:	01c7ac83          	lw	s9,28(a5)
   1084a:	0207ad03          	lw	s10,32(a5)
   1084e:	0247ad83          	lw	s11,36(a5)
   10852:	882a                	mv	a6,a0
   10854:	da840513          	addi	a0,s0,-600
   10858:	972a                	add	a4,a4,a0
   1085a:	02870493          	addi	s1,a4,40
   1085e:	8756                	mv	a4,s5
   10860:	8516                	mv	a0,t0
   10862:	f3872583          	lw	a1,-200(a4)
   10866:	026585bb          	mulw	a1,a1,t1
   1086a:	03658933          	mul	s2,a1,s6
   1086e:	03f95c13          	srli	s8,s2,0x3f
   10872:	f6072983          	lw	s3,-160(a4)
   10876:	42c95613          	srai	a2,s2,0x2c
   1087a:	9662                	add	a2,a2,s8
   1087c:	03760633          	mul	a2,a2,s7
   10880:	027986b3          	mul	a3,s3,t2
   10884:	95b6                	add	a1,a1,a3
   10886:	9d91                	subw	a1,a1,a2
   10888:	03658633          	mul	a2,a1,s6
   1088c:	03f65693          	srli	a3,a2,0x3f
   10890:	f8872783          	lw	a5,-120(a4)
   10894:	9631                	srai	a2,a2,0x2c
   10896:	9636                	add	a2,a2,a3
   10898:	03760633          	mul	a2,a2,s7
   1089c:	03c786b3          	mul	a3,a5,t3
   108a0:	95b6                	add	a1,a1,a3
   108a2:	9d91                	subw	a1,a1,a2
   108a4:	03658633          	mul	a2,a1,s6
   108a8:	03f65693          	srli	a3,a2,0x3f
   108ac:	fb072783          	lw	a5,-80(a4)
   108b0:	9631                	srai	a2,a2,0x2c
   108b2:	9636                	add	a2,a2,a3
   108b4:	03760633          	mul	a2,a2,s7
   108b8:	03d786b3          	mul	a3,a5,t4
   108bc:	95b6                	add	a1,a1,a3
   108be:	9d91                	subw	a1,a1,a2
   108c0:	03658633          	mul	a2,a1,s6
   108c4:	03f65693          	srli	a3,a2,0x3f
   108c8:	fd872783          	lw	a5,-40(a4)
   108cc:	9631                	srai	a2,a2,0x2c
   108ce:	9636                	add	a2,a2,a3
   108d0:	03760633          	mul	a2,a2,s7
   108d4:	03e786b3          	mul	a3,a5,t5
   108d8:	95b6                	add	a1,a1,a3
   108da:	9d91                	subw	a1,a1,a2
   108dc:	03658633          	mul	a2,a1,s6
   108e0:	03f65693          	srli	a3,a2,0x3f
   108e4:	431c                	lw	a5,0(a4)
   108e6:	9631                	srai	a2,a2,0x2c
   108e8:	9636                	add	a2,a2,a3
   108ea:	03760633          	mul	a2,a2,s7
   108ee:	03f786b3          	mul	a3,a5,t6
   108f2:	95b6                	add	a1,a1,a3
   108f4:	9d91                	subw	a1,a1,a2
   108f6:	03658633          	mul	a2,a1,s6
   108fa:	03f65693          	srli	a3,a2,0x3f
   108fe:	571c                	lw	a5,40(a4)
   10900:	9631                	srai	a2,a2,0x2c
   10902:	9636                	add	a2,a2,a3
   10904:	03760633          	mul	a2,a2,s7
   10908:	021786b3          	mul	a3,a5,ra
   1090c:	95b6                	add	a1,a1,a3
   1090e:	9d91                	subw	a1,a1,a2
   10910:	03658633          	mul	a2,a1,s6
   10914:	03f65693          	srli	a3,a2,0x3f
   10918:	4b3c                	lw	a5,80(a4)
   1091a:	9631                	srai	a2,a2,0x2c
   1091c:	9636                	add	a2,a2,a3
   1091e:	03760633          	mul	a2,a2,s7
   10922:	039786b3          	mul	a3,a5,s9
   10926:	95b6                	add	a1,a1,a3
   10928:	9d91                	subw	a1,a1,a2
   1092a:	03658633          	mul	a2,a1,s6
   1092e:	03f65693          	srli	a3,a2,0x3f
   10932:	5f3c                	lw	a5,120(a4)
   10934:	9631                	srai	a2,a2,0x2c
   10936:	9636                	add	a2,a2,a3
   10938:	03760633          	mul	a2,a2,s7
   1093c:	03a786b3          	mul	a3,a5,s10
   10940:	95b6                	add	a1,a1,a3
   10942:	9d91                	subw	a1,a1,a2
   10944:	03658633          	mul	a2,a1,s6
   10948:	03f65693          	srli	a3,a2,0x3f
   1094c:	0a072783          	lw	a5,160(a4)
   10950:	9631                	srai	a2,a2,0x2c
   10952:	9636                	add	a2,a2,a3
   10954:	03760633          	mul	a2,a2,s7
   10958:	03b786b3          	mul	a3,a5,s11
   1095c:	95b6                	add	a1,a1,a3
   1095e:	9d91                	subw	a1,a1,a2
   10960:	03658633          	mul	a2,a1,s6
   10964:	03f65693          	srli	a3,a2,0x3f
   10968:	9631                	srai	a2,a2,0x2c
   1096a:	9636                	add	a2,a2,a3
   1096c:	03760633          	mul	a2,a2,s7
   10970:	9d91                	subw	a1,a1,a2
   10972:	c10c                	sw	a1,0(a0)
   10974:	0511                	addi	a0,a0,4
   10976:	0711                	addi	a4,a4,4
   10978:	ee9515e3          	bne	a0,s1,10862 <.Lpcrel_hi8+0xa4>
   1097c:	00a83513          	sltiu	a0,a6,10
   10980:	9542                	add	a0,a0,a6
   10982:	02828293          	addi	t0,t0,40
   10986:	0885                	addi	a7,a7,1
   10988:	45a9                	li	a1,10
   1098a:	e8b86ae3          	bltu	a6,a1,1081e <.Lpcrel_hi8+0x60>
   1098e:	a8840513          	addi	a0,s0,-1400
   10992:	da840593          	addi	a1,s0,-600
   10996:	19000613          	li	a2,400
   1099a:	00001097          	auipc	ra,0x1
   1099e:	ff8080e7          	jalr	-8(ra) # 11992 <memcpy>
   109a2:	c1840513          	addi	a0,s0,-1000
   109a6:	da840593          	addi	a1,s0,-600
   109aa:	19000613          	li	a2,400
   109ae:	00001097          	auipc	ra,0x1
   109b2:	fe4080e7          	jalr	-28(ra) # 11992 <memcpy>
   109b6:	a7843583          	ld	a1,-1416(s0)
   109ba:	0585                	addi	a1,a1,1
   109bc:	a7043503          	ld	a0,-1424(s0)
   109c0:	e4a599e3          	bne	a1,a0,10812 <.Lpcrel_hi8+0x54>
   109c4:	0ac00893          	li	a7,172
   109c8:	4501                	li	a0,0
   109ca:	4581                	li	a1,0
   109cc:	4601                	li	a2,0
   109ce:	00000073          	ecall
   109d2:	f8a43423          	sd	a0,-120(s0)
   109d6:	f8840513          	addi	a0,s0,-120
   109da:	f2a43c23          	sd	a0,-200(s0)
   109de:	a6843503          	ld	a0,-1432(s0)
   109e2:	f4a43023          	sd	a0,-192(s0)

00000000000109e6 <.Lpcrel_hi9>:
   109e6:	00001517          	auipc	a0,0x1
   109ea:	68a50513          	addi	a0,a0,1674 # 12070 <.Lanon.fad58de7366495db4650cfefac2fcd61.5>
   109ee:	f4a43c23          	sd	a0,-168(s0)
   109f2:	4509                	li	a0,2
   109f4:	f6a43023          	sd	a0,-160(s0)
   109f8:	f6043c23          	sd	zero,-136(s0)
   109fc:	f3840513          	addi	a0,s0,-200
   10a00:	f6a43423          	sd	a0,-152(s0)
   10a04:	4505                	li	a0,1
   10a06:	f6a43823          	sd	a0,-144(s0)
   10a0a:	f5840513          	addi	a0,s0,-168
   10a0e:	00000097          	auipc	ra,0x0
   10a12:	194080e7          	jalr	404(ra) # 10ba2 <_ZN8user_lib7console5print17h77e18570bd382f8eE>
   10a16:	4501                	li	a0,0
   10a18:	00000097          	auipc	ra,0x0
   10a1c:	2ee080e7          	jalr	750(ra) # 10d06 <_ZN8user_lib4exit17h972f8fe61fb14508E>

0000000000010a20 <.Lpcrel_hi1>:
   10a20:	00001517          	auipc	a0,0x1
   10a24:	6c050513          	addi	a0,a0,1728 # 120e0 <.Lanon.fad58de7366495db4650cfefac2fcd61.11>

0000000000010a28 <.Lpcrel_hi2>:
   10a28:	00001597          	auipc	a1,0x1
   10a2c:	6e858613          	addi	a2,a1,1768 # 12110 <.Lanon.fad58de7366495db4650cfefac2fcd61.12>
   10a30:	02a00593          	li	a1,42
   10a34:	00000097          	auipc	ra,0x0
   10a38:	47a080e7          	jalr	1146(ra) # 10eae <_ZN4core9panicking5panic17h026dc666659124b0E>

0000000000010a3c <_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h9905ce31b42f29fbE>:
   10a3c:	1141                	addi	sp,sp,-16
   10a3e:	e406                	sd	ra,8(sp)
   10a40:	e022                	sd	s0,0(sp)
   10a42:	0800                	addi	s0,sp,16
   10a44:	6110                	ld	a2,0(a0)
   10a46:	6514                	ld	a3,8(a0)
   10a48:	872e                	mv	a4,a1
   10a4a:	8532                	mv	a0,a2
   10a4c:	85b6                	mv	a1,a3
   10a4e:	863a                	mv	a2,a4
   10a50:	60a2                	ld	ra,8(sp)
   10a52:	6402                	ld	s0,0(sp)
   10a54:	0141                	addi	sp,sp,16
   10a56:	00001317          	auipc	t1,0x1
   10a5a:	b7230067          	jr	-1166(t1) # 115c8 <_ZN42_$LT$str$u20$as$u20$core..fmt..Display$GT$3fmt17h621f2671cecc6bcaE>

0000000000010a5e <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E>:
   10a5e:	1101                	addi	sp,sp,-32
   10a60:	ec06                	sd	ra,24(sp)
   10a62:	e822                	sd	s0,16(sp)
   10a64:	1000                	addi	s0,sp,32
   10a66:	0005851b          	sext.w	a0,a1
   10a6a:	08000613          	li	a2,128
   10a6e:	fe042623          	sw	zero,-20(s0)
   10a72:	00c57663          	bgeu	a0,a2,10a7e <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E+0x20>
   10a76:	feb40623          	sb	a1,-20(s0)
   10a7a:	4605                	li	a2,1
   10a7c:	a069                	j	10b06 <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E+0xa8>
   10a7e:	00b5d51b          	srliw	a0,a1,0xb
   10a82:	ed19                	bnez	a0,10aa0 <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E+0x42>
   10a84:	0065d513          	srli	a0,a1,0x6
   10a88:	0c056513          	ori	a0,a0,192
   10a8c:	fea40623          	sb	a0,-20(s0)
   10a90:	03f5f513          	andi	a0,a1,63
   10a94:	08050513          	addi	a0,a0,128
   10a98:	fea406a3          	sb	a0,-19(s0)
   10a9c:	4609                	li	a2,2
   10a9e:	a0a5                	j	10b06 <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E+0xa8>
   10aa0:	0105d51b          	srliw	a0,a1,0x10
   10aa4:	e515                	bnez	a0,10ad0 <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E+0x72>
   10aa6:	00c5d513          	srli	a0,a1,0xc
   10aaa:	0e056513          	ori	a0,a0,224
   10aae:	fea40623          	sb	a0,-20(s0)
   10ab2:	03459513          	slli	a0,a1,0x34
   10ab6:	9169                	srli	a0,a0,0x3a
   10ab8:	08050513          	addi	a0,a0,128
   10abc:	fea406a3          	sb	a0,-19(s0)
   10ac0:	03f5f513          	andi	a0,a1,63
   10ac4:	08050513          	addi	a0,a0,128
   10ac8:	fea40723          	sb	a0,-18(s0)
   10acc:	460d                	li	a2,3
   10ace:	a825                	j	10b06 <_ZN4core3fmt5Write10write_char17hcf6cc494df063689E+0xa8>
   10ad0:	0125d513          	srli	a0,a1,0x12
   10ad4:	0f056513          	ori	a0,a0,240
   10ad8:	fea40623          	sb	a0,-20(s0)
   10adc:	02e59513          	slli	a0,a1,0x2e
   10ae0:	9169                	srli	a0,a0,0x3a
   10ae2:	08050513          	addi	a0,a0,128
   10ae6:	fea406a3          	sb	a0,-19(s0)
   10aea:	03459513          	slli	a0,a1,0x34
   10aee:	9169                	srli	a0,a0,0x3a
   10af0:	08050513          	addi	a0,a0,128
   10af4:	fea40723          	sb	a0,-18(s0)
   10af8:	03f5f513          	andi	a0,a1,63
   10afc:	08050513          	addi	a0,a0,128
   10b00:	fea407a3          	sb	a0,-17(s0)
   10b04:	4611                	li	a2,4
   10b06:	4505                	li	a0,1
   10b08:	fec40593          	addi	a1,s0,-20
   10b0c:	04000893          	li	a7,64
   10b10:	00000073          	ecall
   10b14:	4501                	li	a0,0
   10b16:	60e2                	ld	ra,24(sp)
   10b18:	6442                	ld	s0,16(sp)
   10b1a:	6105                	addi	sp,sp,32
   10b1c:	8082                	ret

0000000000010b1e <_ZN4core3fmt5Write9write_fmt17h11b66bd44ba6c943E>:
   10b1e:	1141                	addi	sp,sp,-16
   10b20:	e406                	sd	ra,8(sp)
   10b22:	e022                	sd	s0,0(sp)
   10b24:	0800                	addi	s0,sp,16

0000000000010b26 <.Lpcrel_hi0>:
   10b26:	00001617          	auipc	a2,0x1
   10b2a:	63260613          	addi	a2,a2,1586 # 12158 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.6>
   10b2e:	86ae                	mv	a3,a1
   10b30:	85b2                	mv	a1,a2
   10b32:	8636                	mv	a2,a3
   10b34:	60a2                	ld	ra,8(sp)
   10b36:	6402                	ld	s0,0(sp)
   10b38:	0141                	addi	sp,sp,16
   10b3a:	00000317          	auipc	t1,0x0
   10b3e:	47e30067          	jr	1150(t1) # 10fb8 <_ZN4core3fmt5write17ha9a4e5881bc2248fE>

0000000000010b42 <_ZN53_$LT$core..fmt..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h13e16559e7a5df10E>:
   10b42:	1141                	addi	sp,sp,-16
   10b44:	e406                	sd	ra,8(sp)
   10b46:	e022                	sd	s0,0(sp)
   10b48:	0800                	addi	s0,sp,16

0000000000010b4a <.Lpcrel_hi1>:
   10b4a:	00001517          	auipc	a0,0x1
   10b4e:	60650693          	addi	a3,a0,1542 # 12150 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.0>
   10b52:	4615                	li	a2,5
   10b54:	852e                	mv	a0,a1
   10b56:	85b6                	mv	a1,a3
   10b58:	60a2                	ld	ra,8(sp)
   10b5a:	6402                	ld	s0,0(sp)
   10b5c:	0141                	addi	sp,sp,16
   10b5e:	00001317          	auipc	t1,0x1
   10b62:	a5430067          	jr	-1452(t1) # 115b2 <_ZN4core3fmt9Formatter9write_str17hb7ca0676c07ff6c7E>

0000000000010b66 <_ZN76_$LT$core..panic..panic_info..PanicMessage$u20$as$u20$core..fmt..Display$GT$3fmt17h2959e2eb4e6bba74E>:
   10b66:	1141                	addi	sp,sp,-16
   10b68:	e406                	sd	ra,8(sp)
   10b6a:	e022                	sd	s0,0(sp)
   10b6c:	0800                	addi	s0,sp,16
   10b6e:	7190                	ld	a2,32(a1)
   10b70:	758c                	ld	a1,40(a1)
   10b72:	86aa                	mv	a3,a0
   10b74:	8532                	mv	a0,a2
   10b76:	8636                	mv	a2,a3
   10b78:	60a2                	ld	ra,8(sp)
   10b7a:	6402                	ld	s0,0(sp)
   10b7c:	0141                	addi	sp,sp,16
   10b7e:	00000317          	auipc	t1,0x0
   10b82:	43a30067          	jr	1082(t1) # 10fb8 <_ZN4core3fmt5write17ha9a4e5881bc2248fE>

0000000000010b86 <_ZN62_$LT$user_lib..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17hc4525cec69ae19a4E>:
   10b86:	1141                	addi	sp,sp,-16
   10b88:	e406                	sd	ra,8(sp)
   10b8a:	e022                	sd	s0,0(sp)
   10b8c:	0800                	addi	s0,sp,16
   10b8e:	4505                	li	a0,1
   10b90:	04000893          	li	a7,64
   10b94:	00000073          	ecall
   10b98:	4501                	li	a0,0
   10b9a:	60a2                	ld	ra,8(sp)
   10b9c:	6402                	ld	s0,0(sp)
   10b9e:	0141                	addi	sp,sp,16
   10ba0:	8082                	ret

0000000000010ba2 <_ZN8user_lib7console5print17h77e18570bd382f8eE>:
   10ba2:	1101                	addi	sp,sp,-32
   10ba4:	ec06                	sd	ra,24(sp)
   10ba6:	e822                	sd	s0,16(sp)
   10ba8:	1000                	addi	s0,sp,32
   10baa:	862a                	mv	a2,a0

0000000000010bac <.Lpcrel_hi7>:
   10bac:	00001517          	auipc	a0,0x1
   10bb0:	5ac50593          	addi	a1,a0,1452 # 12158 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.6>
   10bb4:	fef40513          	addi	a0,s0,-17
   10bb8:	00000097          	auipc	ra,0x0
   10bbc:	400080e7          	jalr	1024(ra) # 10fb8 <_ZN4core3fmt5write17ha9a4e5881bc2248fE>
   10bc0:	e509                	bnez	a0,10bca <.Lpcrel_hi8>
   10bc2:	60e2                	ld	ra,24(sp)
   10bc4:	6442                	ld	s0,16(sp)
   10bc6:	6105                	addi	sp,sp,32
   10bc8:	8082                	ret

0000000000010bca <.Lpcrel_hi8>:
   10bca:	00001517          	auipc	a0,0x1
   10bce:	5de50513          	addi	a0,a0,1502 # 121a8 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.8>

0000000000010bd2 <.Lpcrel_hi9>:
   10bd2:	00001597          	auipc	a1,0x1
   10bd6:	5b658693          	addi	a3,a1,1462 # 12188 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.7>

0000000000010bda <.Lpcrel_hi10>:
   10bda:	00001597          	auipc	a1,0x1
   10bde:	60e58713          	addi	a4,a1,1550 # 121e8 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.10>
   10be2:	02b00593          	li	a1,43
   10be6:	fef40613          	addi	a2,s0,-17
   10bea:	00000097          	auipc	ra,0x0
   10bee:	35e080e7          	jalr	862(ra) # 10f48 <_ZN4core6result13unwrap_failed17h509d2b51e226fb0fE>

0000000000010bf2 <rust_begin_unwind>:
   10bf2:	7131                	addi	sp,sp,-192
   10bf4:	fd06                	sd	ra,184(sp)
   10bf6:	f922                	sd	s0,176(sp)
   10bf8:	0180                	addi	s0,sp,192
   10bfa:	750c                	ld	a1,40(a0)
   10bfc:	7110                	ld	a2,32(a0)
   10bfe:	6d14                	ld	a3,24(a0)
   10c00:	f6b43823          	sd	a1,-144(s0)
   10c04:	f6c43423          	sd	a2,-152(s0)
   10c08:	f6d43023          	sd	a3,-160(s0)
   10c0c:	690c                	ld	a1,16(a0)
   10c0e:	6510                	ld	a2,8(a0)
   10c10:	6114                	ld	a3,0(a0)
   10c12:	7908                	ld	a0,48(a0)
   10c14:	f4b43c23          	sd	a1,-168(s0)
   10c18:	f4c43823          	sd	a2,-176(s0)
   10c1c:	f4d43423          	sd	a3,-184(s0)
   10c20:	610c                	ld	a1,0(a0)
   10c22:	6510                	ld	a2,8(a0)
   10c24:	4908                	lw	a0,16(a0)
   10c26:	fcb43c23          	sd	a1,-40(s0)
   10c2a:	fec43023          	sd	a2,-32(s0)
   10c2e:	fea42423          	sw	a0,-24(s0)
   10c32:	fd840513          	addi	a0,s0,-40
   10c36:	faa43423          	sd	a0,-88(s0)

0000000000010c3a <.Lpcrel_hi11>:
   10c3a:	00000517          	auipc	a0,0x0
   10c3e:	e0250513          	addi	a0,a0,-510 # 10a3c <_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h9905ce31b42f29fbE>
   10c42:	faa43823          	sd	a0,-80(s0)
   10c46:	fe840513          	addi	a0,s0,-24
   10c4a:	faa43c23          	sd	a0,-72(s0)

0000000000010c4e <.Lpcrel_hi12>:
   10c4e:	00001517          	auipc	a0,0x1
   10c52:	ca650513          	addi	a0,a0,-858 # 118f4 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$3fmt17h55bc9281ebd53aceE>
   10c56:	fca43023          	sd	a0,-64(s0)
   10c5a:	f4840513          	addi	a0,s0,-184
   10c5e:	fca43423          	sd	a0,-56(s0)

0000000000010c62 <.Lpcrel_hi13>:
   10c62:	00000517          	auipc	a0,0x0
   10c66:	f0450513          	addi	a0,a0,-252 # 10b66 <_ZN76_$LT$core..panic..panic_info..PanicMessage$u20$as$u20$core..fmt..Display$GT$3fmt17h2959e2eb4e6bba74E>
   10c6a:	fca43823          	sd	a0,-48(s0)

0000000000010c6e <.Lpcrel_hi14>:
   10c6e:	00001517          	auipc	a0,0x1
   10c72:	5a250513          	addi	a0,a0,1442 # 12210 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.15>
   10c76:	f6a43c23          	sd	a0,-136(s0)
   10c7a:	4511                	li	a0,4
   10c7c:	f8a43023          	sd	a0,-128(s0)
   10c80:	f8043c23          	sd	zero,-104(s0)
   10c84:	fa840513          	addi	a0,s0,-88
   10c88:	f8a43423          	sd	a0,-120(s0)
   10c8c:	450d                	li	a0,3
   10c8e:	f8a43823          	sd	a0,-112(s0)

0000000000010c92 <.Lpcrel_hi15>:
   10c92:	00001517          	auipc	a0,0x1
   10c96:	4c650593          	addi	a1,a0,1222 # 12158 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.6>
   10c9a:	fef40513          	addi	a0,s0,-17
   10c9e:	f7840613          	addi	a2,s0,-136
   10ca2:	00000097          	auipc	ra,0x0
   10ca6:	316080e7          	jalr	790(ra) # 10fb8 <_ZN4core3fmt5write17ha9a4e5881bc2248fE>
   10caa:	e111                	bnez	a0,10cae <.Lpcrel_hi16>
   10cac:	a001                	j	10cac <.Lpcrel_hi15+0x1a>

0000000000010cae <.Lpcrel_hi16>:
   10cae:	00001517          	auipc	a0,0x1
   10cb2:	4fa50513          	addi	a0,a0,1274 # 121a8 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.8>

0000000000010cb6 <.Lpcrel_hi17>:
   10cb6:	00001597          	auipc	a1,0x1
   10cba:	4d258693          	addi	a3,a1,1234 # 12188 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.7>

0000000000010cbe <.Lpcrel_hi18>:
   10cbe:	00001597          	auipc	a1,0x1
   10cc2:	52a58713          	addi	a4,a1,1322 # 121e8 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.10>
   10cc6:	02b00593          	li	a1,43
   10cca:	fef40613          	addi	a2,s0,-17
   10cce:	00000097          	auipc	ra,0x0
   10cd2:	27a080e7          	jalr	634(ra) # 10f48 <_ZN4core6result13unwrap_failed17h509d2b51e226fb0fE>

0000000000010cd6 <_ZN8user_lib7syscall8sys_exit17hec9bcab0751dcbb3E>:
   10cd6:	1141                	addi	sp,sp,-16
   10cd8:	e406                	sd	ra,8(sp)
   10cda:	e022                	sd	s0,0(sp)
   10cdc:	0800                	addi	s0,sp,16
   10cde:	2501                	sext.w	a0,a0
   10ce0:	05d00893          	li	a7,93
   10ce4:	4581                	li	a1,0
   10ce6:	4601                	li	a2,0
   10ce8:	00000073          	ecall

0000000000010cec <.Lpcrel_hi19>:
   10cec:	00001517          	auipc	a0,0x1
   10cf0:	56450513          	addi	a0,a0,1380 # 12250 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.16>

0000000000010cf4 <.Lpcrel_hi20>:
   10cf4:	00001597          	auipc	a1,0x1
   10cf8:	58458613          	addi	a2,a1,1412 # 12278 <.Lanon.7060f26e7f715dd4170bfd56f1ea8789.18>
   10cfc:	45dd                	li	a1,23
   10cfe:	00000097          	auipc	ra,0x0
   10d02:	1b0080e7          	jalr	432(ra) # 10eae <_ZN4core9panicking5panic17h026dc666659124b0E>

0000000000010d06 <_ZN8user_lib4exit17h972f8fe61fb14508E>:
   10d06:	1141                	addi	sp,sp,-16
   10d08:	e406                	sd	ra,8(sp)
   10d0a:	e022                	sd	s0,0(sp)
   10d0c:	0800                	addi	s0,sp,16
   10d0e:	00000097          	auipc	ra,0x0
   10d12:	fc8080e7          	jalr	-56(ra) # 10cd6 <_ZN8user_lib7syscall8sys_exit17hec9bcab0751dcbb3E>

0000000000010d16 <_ZN22buddy_system_allocator4Heap4init17h00d5b3cec7a683d4E>:
   10d16:	1141                	addi	sp,sp,-16
   10d18:	e406                	sd	ra,8(sp)
   10d1a:	e022                	sd	s0,0(sp)
   10d1c:	0800                	addi	s0,sp,16
   10d1e:	962e                	add	a2,a2,a1
   10d20:	059d                	addi	a1,a1,7
   10d22:	ff85f793          	andi	a5,a1,-8
   10d26:	ff867f93          	andi	t6,a2,-8
   10d2a:	12ffe463          	bltu	t6,a5,10e52 <.Lpcrel_hi39>
   10d2e:	4701                	li	a4,0
   10d30:	00878593          	addi	a1,a5,8
   10d34:	0ebfeb63          	bltu	t6,a1,10e2a <.Lpcrel_hi38+0xae>
   10d38:	4805                	li	a6,1
   10d3a:	48fd                	li	a7,31

0000000000010d3c <.Lpcrel_hi37>:
   10d3c:	00001597          	auipc	a1,0x1
   10d40:	32c5b283          	ld	t0,812(a1) # 12068 <$d+0x8>
   10d44:	555555b7          	lui	a1,0x55555
   10d48:	5555831b          	addiw	t1,a1,1365
   10d4c:	02031593          	slli	a1,t1,0x20
   10d50:	932e                	add	t1,t1,a1
   10d52:	333335b7          	lui	a1,0x33333
   10d56:	33358f1b          	addiw	t5,a1,819
   10d5a:	020f1593          	slli	a1,t5,0x20
   10d5e:	9f2e                	add	t5,t5,a1
   10d60:	0f0f15b7          	lui	a1,0xf0f1
   10d64:	f0f5839b          	addiw	t2,a1,-241
   10d68:	02039593          	slli	a1,t2,0x20
   10d6c:	93ae                	add	t2,t2,a1
   10d6e:	010105b7          	lui	a1,0x1010
   10d72:	10158e1b          	addiw	t3,a1,257
   10d76:	020e1593          	slli	a1,t3,0x20
   10d7a:	9e2e                	add	t3,t3,a1

0000000000010d7c <.Lpcrel_hi38>:
   10d7c:	00001597          	auipc	a1,0x1
   10d80:	65458e93          	addi	t4,a1,1620 # 123d0 <.LCPI13_1>
   10d84:	40ff85b3          	sub	a1,t6,a5
   10d88:	c9a9                	beqz	a1,10dda <.Lpcrel_hi38+0x5e>
   10d8a:	0015d693          	srli	a3,a1,0x1
   10d8e:	8dd5                	or	a1,a1,a3
   10d90:	0025d693          	srli	a3,a1,0x2
   10d94:	8dd5                	or	a1,a1,a3
   10d96:	0045d693          	srli	a3,a1,0x4
   10d9a:	8dd5                	or	a1,a1,a3
   10d9c:	0085d693          	srli	a3,a1,0x8
   10da0:	8dd5                	or	a1,a1,a3
   10da2:	0105d693          	srli	a3,a1,0x10
   10da6:	8dd5                	or	a1,a1,a3
   10da8:	0205d693          	srli	a3,a1,0x20
   10dac:	8dd5                	or	a1,a1,a3
   10dae:	fff5c593          	not	a1,a1
   10db2:	0015d693          	srli	a3,a1,0x1
   10db6:	0066f6b3          	and	a3,a3,t1
   10dba:	8d95                	sub	a1,a1,a3
   10dbc:	01e5f6b3          	and	a3,a1,t5
   10dc0:	8189                	srli	a1,a1,0x2
   10dc2:	01e5f5b3          	and	a1,a1,t5
   10dc6:	95b6                	add	a1,a1,a3
   10dc8:	0045d693          	srli	a3,a1,0x4
   10dcc:	95b6                	add	a1,a1,a3
   10dce:	0075f5b3          	and	a1,a1,t2
   10dd2:	03c586b3          	mul	a3,a1,t3
   10dd6:	92e1                	srli	a3,a3,0x38
   10dd8:	a019                	j	10dde <.Lpcrel_hi38+0x62>
   10dda:	04000693          	li	a3,64
   10dde:	40f005b3          	neg	a1,a5
   10de2:	8dfd                	and	a1,a1,a5
   10de4:	fff6c693          	not	a3,a3
   10de8:	00d816b3          	sll	a3,a6,a3
   10dec:	00d5e363          	bltu	a1,a3,10df2 <.Lpcrel_hi38+0x76>
   10df0:	85b6                	mv	a1,a3
   10df2:	cd89                	beqz	a1,10e0c <.Lpcrel_hi38+0x90>
   10df4:	40b006b3          	neg	a3,a1
   10df8:	8eed                	and	a3,a3,a1
   10dfa:	025686b3          	mul	a3,a3,t0
   10dfe:	92e9                	srli	a3,a3,0x3a
   10e00:	96f6                	add	a3,a3,t4
   10e02:	0006c683          	lbu	a3,0(a3)
   10e06:	00d8f763          	bgeu	a7,a3,10e14 <.Lpcrel_hi38+0x98>
   10e0a:	a80d                	j	10e3c <.Lpcrel_hi41>
   10e0c:	04000693          	li	a3,64
   10e10:	02d8e663          	bltu	a7,a3,10e3c <.Lpcrel_hi41>
   10e14:	068e                	slli	a3,a3,0x3
   10e16:	96aa                	add	a3,a3,a0
   10e18:	6290                	ld	a2,0(a3)
   10e1a:	e390                	sd	a2,0(a5)
   10e1c:	e29c                	sd	a5,0(a3)
   10e1e:	97ae                	add	a5,a5,a1
   10e20:	00878613          	addi	a2,a5,8
   10e24:	972e                	add	a4,a4,a1
   10e26:	f4cfffe3          	bgeu	t6,a2,10d84 <.Lpcrel_hi38+0x8>
   10e2a:	11053583          	ld	a1,272(a0)
   10e2e:	95ba                	add	a1,a1,a4
   10e30:	10b53823          	sd	a1,272(a0)
   10e34:	60a2                	ld	ra,8(sp)
   10e36:	6402                	ld	s0,0(sp)
   10e38:	0141                	addi	sp,sp,16
   10e3a:	8082                	ret

0000000000010e3c <.Lpcrel_hi41>:
   10e3c:	00001517          	auipc	a0,0x1
   10e40:	6f450613          	addi	a2,a0,1780 # 12530 <.Lanon.fe7a7a38281cefab3687c3134c1529c3.15>
   10e44:	02000593          	li	a1,32
   10e48:	8536                	mv	a0,a3
   10e4a:	00000097          	auipc	ra,0x0
   10e4e:	09e080e7          	jalr	158(ra) # 10ee8 <_ZN4core9panicking18panic_bounds_check17hf79e280c32e5af2eE>

0000000000010e52 <.Lpcrel_hi39>:
   10e52:	00001517          	auipc	a0,0x1
   10e56:	63e50513          	addi	a0,a0,1598 # 12490 <.Lanon.fe7a7a38281cefab3687c3134c1529c3.6>

0000000000010e5a <.Lpcrel_hi40>:
   10e5a:	00001597          	auipc	a1,0x1
   10e5e:	6be58613          	addi	a2,a1,1726 # 12518 <.Lanon.fe7a7a38281cefab3687c3134c1529c3.14>
   10e62:	45f9                	li	a1,30
   10e64:	00000097          	auipc	ra,0x0
   10e68:	04a080e7          	jalr	74(ra) # 10eae <_ZN4core9panicking5panic17h026dc666659124b0E>

0000000000010e6c <_ZN4core9panicking9panic_fmt17h484df8a389ef2dd8E>:
   10e6c:	715d                	addi	sp,sp,-80
   10e6e:	e486                	sd	ra,72(sp)
   10e70:	e0a2                	sd	s0,64(sp)
   10e72:	0880                	addi	s0,sp,80
   10e74:	7510                	ld	a2,40(a0)
   10e76:	7114                	ld	a3,32(a0)
   10e78:	fcc43c23          	sd	a2,-40(s0)
   10e7c:	fcd43823          	sd	a3,-48(s0)
   10e80:	6d10                	ld	a2,24(a0)
   10e82:	6914                	ld	a3,16(a0)
   10e84:	6518                	ld	a4,8(a0)
   10e86:	6108                	ld	a0,0(a0)
   10e88:	fcc43423          	sd	a2,-56(s0)
   10e8c:	fcd43023          	sd	a3,-64(s0)
   10e90:	fae43c23          	sd	a4,-72(s0)
   10e94:	faa43823          	sd	a0,-80(s0)
   10e98:	feb43023          	sd	a1,-32(s0)
   10e9c:	4505                	li	a0,1
   10e9e:	fea41423          	sh	a0,-24(s0)
   10ea2:	fb040513          	addi	a0,s0,-80
   10ea6:	00000097          	auipc	ra,0x0
   10eaa:	d4c080e7          	jalr	-692(ra) # 10bf2 <rust_begin_unwind>

0000000000010eae <_ZN4core9panicking5panic17h026dc666659124b0E>:
   10eae:	715d                	addi	sp,sp,-80
   10eb0:	e486                	sd	ra,72(sp)
   10eb2:	e0a2                	sd	s0,64(sp)
   10eb4:	0880                	addi	s0,sp,80
   10eb6:	fea43023          	sd	a0,-32(s0)
   10eba:	feb43423          	sd	a1,-24(s0)
   10ebe:	fe040513          	addi	a0,s0,-32
   10ec2:	faa43823          	sd	a0,-80(s0)
   10ec6:	4505                	li	a0,1
   10ec8:	faa43c23          	sd	a0,-72(s0)
   10ecc:	fc043823          	sd	zero,-48(s0)
   10ed0:	4521                	li	a0,8
   10ed2:	fca43023          	sd	a0,-64(s0)
   10ed6:	fc043423          	sd	zero,-56(s0)
   10eda:	fb040513          	addi	a0,s0,-80
   10ede:	85b2                	mv	a1,a2
   10ee0:	00000097          	auipc	ra,0x0
   10ee4:	f8c080e7          	jalr	-116(ra) # 10e6c <_ZN4core9panicking9panic_fmt17h484df8a389ef2dd8E>

0000000000010ee8 <_ZN4core9panicking18panic_bounds_check17hf79e280c32e5af2eE>:
   10ee8:	7159                	addi	sp,sp,-112
   10eea:	f486                	sd	ra,104(sp)
   10eec:	f0a2                	sd	s0,96(sp)
   10eee:	1880                	addi	s0,sp,112
   10ef0:	f8a43823          	sd	a0,-112(s0)
   10ef4:	f8b43c23          	sd	a1,-104(s0)
   10ef8:	f9840513          	addi	a0,s0,-104
   10efc:	fca43823          	sd	a0,-48(s0)

0000000000010f00 <.Lpcrel_hi345>:
   10f00:	00001517          	auipc	a0,0x1
   10f04:	a4250513          	addi	a0,a0,-1470 # 11942 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u64$GT$3fmt17hbebc74f197ec876aE>
   10f08:	fca43c23          	sd	a0,-40(s0)
   10f0c:	f9040593          	addi	a1,s0,-112
   10f10:	feb43023          	sd	a1,-32(s0)
   10f14:	fea43423          	sd	a0,-24(s0)

0000000000010f18 <.Lpcrel_hi346>:
   10f18:	00001517          	auipc	a0,0x1
   10f1c:	66850513          	addi	a0,a0,1640 # 12580 <.Lanon.10f909bc3d7870a0109061ce2530e04d.237>
   10f20:	faa43023          	sd	a0,-96(s0)
   10f24:	4509                	li	a0,2
   10f26:	faa43423          	sd	a0,-88(s0)
   10f2a:	fc043023          	sd	zero,-64(s0)
   10f2e:	fd040593          	addi	a1,s0,-48
   10f32:	fab43823          	sd	a1,-80(s0)
   10f36:	faa43c23          	sd	a0,-72(s0)
   10f3a:	fa040513          	addi	a0,s0,-96
   10f3e:	85b2                	mv	a1,a2
   10f40:	00000097          	auipc	ra,0x0
   10f44:	f2c080e7          	jalr	-212(ra) # 10e6c <_ZN4core9panicking9panic_fmt17h484df8a389ef2dd8E>

0000000000010f48 <_ZN4core6result13unwrap_failed17h509d2b51e226fb0fE>:
   10f48:	7119                	addi	sp,sp,-128
   10f4a:	fc86                	sd	ra,120(sp)
   10f4c:	f8a2                	sd	s0,112(sp)
   10f4e:	0100                	addi	s0,sp,128
   10f50:	f8a43023          	sd	a0,-128(s0)
   10f54:	f8b43423          	sd	a1,-120(s0)
   10f58:	f8c43823          	sd	a2,-112(s0)
   10f5c:	f8d43c23          	sd	a3,-104(s0)
   10f60:	f8040513          	addi	a0,s0,-128
   10f64:	fca43823          	sd	a0,-48(s0)

0000000000010f68 <.Lpcrel_hi368>:
   10f68:	00001517          	auipc	a0,0x1
   10f6c:	a0c50513          	addi	a0,a0,-1524 # 11974 <_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h2e1e8d2633c3d1cfE>
   10f70:	fca43c23          	sd	a0,-40(s0)
   10f74:	f9040513          	addi	a0,s0,-112
   10f78:	fea43023          	sd	a0,-32(s0)

0000000000010f7c <.Lpcrel_hi369>:
   10f7c:	00001517          	auipc	a0,0x1
   10f80:	9e250513          	addi	a0,a0,-1566 # 1195e <_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17ha805f7b075431583E>
   10f84:	fea43423          	sd	a0,-24(s0)

0000000000010f88 <.Lpcrel_hi370>:
   10f88:	00001517          	auipc	a0,0x1
   10f8c:	62050513          	addi	a0,a0,1568 # 125a8 <.Lanon.10f909bc3d7870a0109061ce2530e04d.257>
   10f90:	faa43023          	sd	a0,-96(s0)
   10f94:	4509                	li	a0,2
   10f96:	faa43423          	sd	a0,-88(s0)
   10f9a:	fc043023          	sd	zero,-64(s0)
   10f9e:	fd040593          	addi	a1,s0,-48
   10fa2:	fab43823          	sd	a1,-80(s0)
   10fa6:	faa43c23          	sd	a0,-72(s0)
   10faa:	fa040513          	addi	a0,s0,-96
   10fae:	85ba                	mv	a1,a4
   10fb0:	00000097          	auipc	ra,0x0
   10fb4:	ebc080e7          	jalr	-324(ra) # 10e6c <_ZN4core9panicking9panic_fmt17h484df8a389ef2dd8E>

0000000000010fb8 <_ZN4core3fmt5write17ha9a4e5881bc2248fE>:
   10fb8:	7175                	addi	sp,sp,-144
   10fba:	e506                	sd	ra,136(sp)
   10fbc:	e122                	sd	s0,128(sp)
   10fbe:	fca6                	sd	s1,120(sp)
   10fc0:	f8ca                	sd	s2,112(sp)
   10fc2:	f4ce                	sd	s3,104(sp)
   10fc4:	f0d2                	sd	s4,96(sp)
   10fc6:	ecd6                	sd	s5,88(sp)
   10fc8:	e8da                	sd	s6,80(sp)
   10fca:	e4de                	sd	s7,72(sp)
   10fcc:	e0e2                	sd	s8,64(sp)
   10fce:	0900                	addi	s0,sp,144
   10fd0:	89b2                	mv	s3,a2
   10fd2:	02000613          	li	a2,32
   10fd6:	fac43023          	sd	a2,-96(s0)
   10fda:	460d                	li	a2,3
   10fdc:	fac40423          	sb	a2,-88(s0)
   10fe0:	0209b483          	ld	s1,32(s3)
   10fe4:	f6043823          	sd	zero,-144(s0)
   10fe8:	f8043023          	sd	zero,-128(s0)
   10fec:	f8a43823          	sd	a0,-112(s0)
   10ff0:	f8b43c23          	sd	a1,-104(s0)
   10ff4:	c8f9                	beqz	s1,110ca <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x112>
   10ff6:	0289b503          	ld	a0,40(s3)
   10ffa:	12050663          	beqz	a0,11126 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x16e>
   10ffe:	0009bb03          	ld	s6,0(s3)
   11002:	0109ba03          	ld	s4,16(s3)
   11006:	fff50593          	addi	a1,a0,-1
   1100a:	058e                	slli	a1,a1,0x3
   1100c:	818d                	srli	a1,a1,0x3
   1100e:	00158913          	addi	s2,a1,1
   11012:	0b21                	addi	s6,s6,8
   11014:	00351593          	slli	a1,a0,0x3
   11018:	051a                	slli	a0,a0,0x6
   1101a:	40b50ab3          	sub	s5,a0,a1
   1101e:	04e1                	addi	s1,s1,24
   11020:	4b89                	li	s7,2
   11022:	4c05                	li	s8,1
   11024:	000b3603          	ld	a2,0(s6)
   11028:	ca19                	beqz	a2,1103e <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x86>
   1102a:	f9843683          	ld	a3,-104(s0)
   1102e:	f9043503          	ld	a0,-112(s0)
   11032:	ff8b3583          	ld	a1,-8(s6)
   11036:	6e94                	ld	a3,24(a3)
   11038:	9682                	jalr	a3
   1103a:	10051a63          	bnez	a0,1114e <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x196>
   1103e:	6888                	ld	a0,16(s1)
   11040:	faa43023          	sd	a0,-96(s0)
   11044:	0184c603          	lbu	a2,24(s1)
   11048:	ff84b583          	ld	a1,-8(s1)
   1104c:	6088                	ld	a0,0(s1)
   1104e:	fac40423          	sb	a2,-88(s0)
   11052:	c18d                	beqz	a1,11074 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xbc>
   11054:	01859663          	bne	a1,s8,11060 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xa8>
   11058:	0512                	slli	a0,a0,0x4
   1105a:	9552                	add	a0,a0,s4
   1105c:	650c                	ld	a1,8(a0)
   1105e:	c991                	beqz	a1,11072 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xba>
   11060:	fe84b603          	ld	a2,-24(s1)
   11064:	f6043823          	sd	zero,-144(s0)
   11068:	f6a43c23          	sd	a0,-136(s0)
   1106c:	01761d63          	bne	a2,s7,11086 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xce>
   11070:	a025                	j	11098 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xe0>
   11072:	6108                	ld	a0,0(a0)
   11074:	4585                	li	a1,1
   11076:	fe84b603          	ld	a2,-24(s1)
   1107a:	f6b43823          	sd	a1,-144(s0)
   1107e:	f6a43c23          	sd	a0,-136(s0)
   11082:	01760b63          	beq	a2,s7,11098 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xe0>
   11086:	ff04b583          	ld	a1,-16(s1)
   1108a:	01861a63          	bne	a2,s8,1109e <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xe6>
   1108e:	00459513          	slli	a0,a1,0x4
   11092:	9552                	add	a0,a0,s4
   11094:	650c                	ld	a1,8(a0)
   11096:	c199                	beqz	a1,1109c <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xe4>
   11098:	4601                	li	a2,0
   1109a:	a019                	j	110a0 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0xe8>
   1109c:	610c                	ld	a1,0(a0)
   1109e:	4605                	li	a2,1
   110a0:	6488                	ld	a0,8(s1)
   110a2:	0512                	slli	a0,a0,0x4
   110a4:	9552                	add	a0,a0,s4
   110a6:	6514                	ld	a3,8(a0)
   110a8:	6108                	ld	a0,0(a0)
   110aa:	f8c43023          	sd	a2,-128(s0)
   110ae:	f8b43423          	sd	a1,-120(s0)
   110b2:	f7040593          	addi	a1,s0,-144
   110b6:	9682                	jalr	a3
   110b8:	e959                	bnez	a0,1114e <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x196>
   110ba:	0b41                	addi	s6,s6,16
   110bc:	fc8a8a93          	addi	s5,s5,-56
   110c0:	03848493          	addi	s1,s1,56
   110c4:	f60a90e3          	bnez	s5,11024 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x6c>
   110c8:	a891                	j	1111c <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x164>
   110ca:	0189ba03          	ld	s4,24(s3)
   110ce:	040a0c63          	beqz	s4,11126 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x16e>
   110d2:	0109b483          	ld	s1,16(s3)
   110d6:	0009ba83          	ld	s5,0(s3)
   110da:	fffa0513          	addi	a0,s4,-1
   110de:	0512                	slli	a0,a0,0x4
   110e0:	8111                	srli	a0,a0,0x4
   110e2:	00150913          	addi	s2,a0,1
   110e6:	0aa1                	addi	s5,s5,8
   110e8:	0a12                	slli	s4,s4,0x4
   110ea:	04a1                	addi	s1,s1,8
   110ec:	000ab603          	ld	a2,0(s5)
   110f0:	ca11                	beqz	a2,11104 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x14c>
   110f2:	f9843683          	ld	a3,-104(s0)
   110f6:	f9043503          	ld	a0,-112(s0)
   110fa:	ff8ab583          	ld	a1,-8(s5)
   110fe:	6e94                	ld	a3,24(a3)
   11100:	9682                	jalr	a3
   11102:	e531                	bnez	a0,1114e <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x196>
   11104:	6090                	ld	a2,0(s1)
   11106:	ff84b503          	ld	a0,-8(s1)
   1110a:	f7040593          	addi	a1,s0,-144
   1110e:	9602                	jalr	a2
   11110:	ed1d                	bnez	a0,1114e <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x196>
   11112:	0ac1                	addi	s5,s5,16
   11114:	1a41                	addi	s4,s4,-16
   11116:	04c1                	addi	s1,s1,16
   11118:	fc0a1ae3          	bnez	s4,110ec <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x134>
   1111c:	0089b503          	ld	a0,8(s3)
   11120:	00a96863          	bltu	s2,a0,11130 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x178>
   11124:	a03d                	j	11152 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x19a>
   11126:	4901                	li	s2,0
   11128:	0089b503          	ld	a0,8(s3)
   1112c:	02a07363          	bgeu	zero,a0,11152 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x19a>
   11130:	0009b503          	ld	a0,0(s3)
   11134:	0912                	slli	s2,s2,0x4
   11136:	992a                	add	s2,s2,a0
   11138:	f9843683          	ld	a3,-104(s0)
   1113c:	f9043503          	ld	a0,-112(s0)
   11140:	00093583          	ld	a1,0(s2)
   11144:	00893603          	ld	a2,8(s2)
   11148:	6e94                	ld	a3,24(a3)
   1114a:	9682                	jalr	a3
   1114c:	c119                	beqz	a0,11152 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x19a>
   1114e:	4505                	li	a0,1
   11150:	a011                	j	11154 <_ZN4core3fmt5write17ha9a4e5881bc2248fE+0x19c>
   11152:	4501                	li	a0,0
   11154:	60aa                	ld	ra,136(sp)
   11156:	640a                	ld	s0,128(sp)
   11158:	74e6                	ld	s1,120(sp)
   1115a:	7946                	ld	s2,112(sp)
   1115c:	79a6                	ld	s3,104(sp)
   1115e:	7a06                	ld	s4,96(sp)
   11160:	6ae6                	ld	s5,88(sp)
   11162:	6b46                	ld	s6,80(sp)
   11164:	6ba6                	ld	s7,72(sp)
   11166:	6c06                	ld	s8,64(sp)
   11168:	6149                	addi	sp,sp,144
   1116a:	8082                	ret

000000000001116c <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E>:
   1116c:	7159                	addi	sp,sp,-112
   1116e:	f486                	sd	ra,104(sp)
   11170:	f0a2                	sd	s0,96(sp)
   11172:	eca6                	sd	s1,88(sp)
   11174:	e8ca                	sd	s2,80(sp)
   11176:	e4ce                	sd	s3,72(sp)
   11178:	e0d2                	sd	s4,64(sp)
   1117a:	fc56                	sd	s5,56(sp)
   1117c:	f85a                	sd	s6,48(sp)
   1117e:	f45e                	sd	s7,40(sp)
   11180:	f062                	sd	s8,32(sp)
   11182:	ec66                	sd	s9,24(sp)
   11184:	e86a                	sd	s10,16(sp)
   11186:	e46e                	sd	s11,8(sp)
   11188:	1880                	addi	s0,sp,112
   1118a:	89be                	mv	s3,a5
   1118c:	893a                	mv	s2,a4
   1118e:	8a36                	mv	s4,a3
   11190:	8b32                	mv	s6,a2
   11192:	c5b9                	beqz	a1,111e0 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x74>
   11194:	03456483          	lwu	s1,52(a0)
   11198:	0014fc13          	andi	s8,s1,1
   1119c:	00110ab7          	lui	s5,0x110
   111a0:	000c0463          	beqz	s8,111a8 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x3c>
   111a4:	02b00a93          	li	s5,43
   111a8:	9c4e                	add	s8,s8,s3
   111aa:	0044f593          	andi	a1,s1,4
   111ae:	c1a9                	beqz	a1,111f0 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x84>
   111b0:	02000593          	li	a1,32
   111b4:	04ba7263          	bgeu	s4,a1,111f8 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x8c>
   111b8:	4581                	li	a1,0
   111ba:	000a0f63          	beqz	s4,111d8 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x6c>
   111be:	014b0633          	add	a2,s6,s4
   111c2:	86da                	mv	a3,s6
   111c4:	00068703          	lb	a4,0(a3)
   111c8:	fc072713          	slti	a4,a4,-64
   111cc:	00174713          	xori	a4,a4,1
   111d0:	0685                	addi	a3,a3,1
   111d2:	95ba                	add	a1,a1,a4
   111d4:	fec698e3          	bne	a3,a2,111c4 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x58>
   111d8:	9c2e                	add	s8,s8,a1
   111da:	610c                	ld	a1,0(a0)
   111dc:	c9b1                	beqz	a1,11230 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0xc4>
   111de:	a815                	j	11212 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0xa6>
   111e0:	5944                	lw	s1,52(a0)
   111e2:	00198c13          	addi	s8,s3,1
   111e6:	02d00a93          	li	s5,45
   111ea:	0044f593          	andi	a1,s1,4
   111ee:	f1e9                	bnez	a1,111b0 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x44>
   111f0:	4b01                	li	s6,0
   111f2:	610c                	ld	a1,0(a0)
   111f4:	ed99                	bnez	a1,11212 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0xa6>
   111f6:	a82d                	j	11230 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0xc4>
   111f8:	8baa                	mv	s7,a0
   111fa:	855a                	mv	a0,s6
   111fc:	85d2                	mv	a1,s4
   111fe:	00000097          	auipc	ra,0x0
   11202:	3e8080e7          	jalr	1000(ra) # 115e6 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E>
   11206:	85aa                	mv	a1,a0
   11208:	855e                	mv	a0,s7
   1120a:	9c2e                	add	s8,s8,a1
   1120c:	000bb583          	ld	a1,0(s7)
   11210:	c185                	beqz	a1,11230 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0xc4>
   11212:	00853c83          	ld	s9,8(a0)
   11216:	019c7d63          	bgeu	s8,s9,11230 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0xc4>
   1121a:	88a1                	andi	s1,s1,8
   1121c:	eca1                	bnez	s1,11274 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x108>
   1121e:	03854583          	lbu	a1,56(a0)
   11222:	4605                	li	a2,1
   11224:	418c8cb3          	sub	s9,s9,s8
   11228:	08b64e63          	blt	a2,a1,112c4 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x158>
   1122c:	c5dd                	beqz	a1,112da <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x16e>
   1122e:	a065                	j	112d6 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x16a>
   11230:	02053b83          	ld	s7,32(a0)
   11234:	7504                	ld	s1,40(a0)
   11236:	855e                	mv	a0,s7
   11238:	85a6                	mv	a1,s1
   1123a:	8656                	mv	a2,s5
   1123c:	86da                	mv	a3,s6
   1123e:	8752                	mv	a4,s4
   11240:	00000097          	auipc	ra,0x0
   11244:	150080e7          	jalr	336(ra) # 11390 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE>
   11248:	85aa                	mv	a1,a0
   1124a:	4505                	li	a0,1
   1124c:	e9c5                	bnez	a1,112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>
   1124e:	6c9c                	ld	a5,24(s1)
   11250:	855e                	mv	a0,s7
   11252:	85ca                	mv	a1,s2
   11254:	864e                	mv	a2,s3
   11256:	70a6                	ld	ra,104(sp)
   11258:	7406                	ld	s0,96(sp)
   1125a:	64e6                	ld	s1,88(sp)
   1125c:	6946                	ld	s2,80(sp)
   1125e:	69a6                	ld	s3,72(sp)
   11260:	6a06                	ld	s4,64(sp)
   11262:	7ae2                	ld	s5,56(sp)
   11264:	7b42                	ld	s6,48(sp)
   11266:	7ba2                	ld	s7,40(sp)
   11268:	7c02                	ld	s8,32(sp)
   1126a:	6ce2                	ld	s9,24(sp)
   1126c:	6d42                	ld	s10,16(sp)
   1126e:	6da2                	ld	s11,8(sp)
   11270:	6165                	addi	sp,sp,112
   11272:	8782                	jr	a5
   11274:	5904                	lw	s1,48(a0)
   11276:	03000593          	li	a1,48
   1127a:	03854603          	lbu	a2,56(a0)
   1127e:	f8c43823          	sd	a2,-112(s0)
   11282:	02053b83          	ld	s7,32(a0)
   11286:	02853d03          	ld	s10,40(a0)
   1128a:	d90c                	sw	a1,48(a0)
   1128c:	4585                	li	a1,1
   1128e:	8daa                	mv	s11,a0
   11290:	02b50c23          	sb	a1,56(a0)
   11294:	855e                	mv	a0,s7
   11296:	85ea                	mv	a1,s10
   11298:	8656                	mv	a2,s5
   1129a:	86da                	mv	a3,s6
   1129c:	8752                	mv	a4,s4
   1129e:	00000097          	auipc	ra,0x0
   112a2:	0f2080e7          	jalr	242(ra) # 11390 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE>
   112a6:	e931                	bnez	a0,112fa <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x18e>
   112a8:	8a26                	mv	s4,s1
   112aa:	418c84b3          	sub	s1,s9,s8
   112ae:	0485                	addi	s1,s1,1
   112b0:	14fd                	addi	s1,s1,-1
   112b2:	c8dd                	beqz	s1,11368 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x1fc>
   112b4:	020d3603          	ld	a2,32(s10)
   112b8:	03000593          	li	a1,48
   112bc:	855e                	mv	a0,s7
   112be:	9602                	jalr	a2
   112c0:	d965                	beqz	a0,112b0 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x144>
   112c2:	a825                	j	112fa <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x18e>
   112c4:	4609                	li	a2,2
   112c6:	00c59863          	bne	a1,a2,112d6 <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x16a>
   112ca:	001cd593          	srli	a1,s9,0x1
   112ce:	0c85                	addi	s9,s9,1
   112d0:	001cdc93          	srli	s9,s9,0x1
   112d4:	a019                	j	112da <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x16e>
   112d6:	85e6                	mv	a1,s9
   112d8:	4c81                	li	s9,0
   112da:	02053b83          	ld	s7,32(a0)
   112de:	02853d03          	ld	s10,40(a0)
   112e2:	03052c03          	lw	s8,48(a0)
   112e6:	00158493          	addi	s1,a1,1
   112ea:	14fd                	addi	s1,s1,-1
   112ec:	c49d                	beqz	s1,1131a <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x1ae>
   112ee:	020d3603          	ld	a2,32(s10)
   112f2:	855e                	mv	a0,s7
   112f4:	85e2                	mv	a1,s8
   112f6:	9602                	jalr	a2
   112f8:	d96d                	beqz	a0,112ea <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x17e>
   112fa:	4505                	li	a0,1
   112fc:	70a6                	ld	ra,104(sp)
   112fe:	7406                	ld	s0,96(sp)
   11300:	64e6                	ld	s1,88(sp)
   11302:	6946                	ld	s2,80(sp)
   11304:	69a6                	ld	s3,72(sp)
   11306:	6a06                	ld	s4,64(sp)
   11308:	7ae2                	ld	s5,56(sp)
   1130a:	7b42                	ld	s6,48(sp)
   1130c:	7ba2                	ld	s7,40(sp)
   1130e:	7c02                	ld	s8,32(sp)
   11310:	6ce2                	ld	s9,24(sp)
   11312:	6d42                	ld	s10,16(sp)
   11314:	6da2                	ld	s11,8(sp)
   11316:	6165                	addi	sp,sp,112
   11318:	8082                	ret
   1131a:	855e                	mv	a0,s7
   1131c:	85ea                	mv	a1,s10
   1131e:	8656                	mv	a2,s5
   11320:	86da                	mv	a3,s6
   11322:	8752                	mv	a4,s4
   11324:	00000097          	auipc	ra,0x0
   11328:	06c080e7          	jalr	108(ra) # 11390 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE>
   1132c:	85aa                	mv	a1,a0
   1132e:	4505                	li	a0,1
   11330:	f5f1                	bnez	a1,112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>
   11332:	018d3683          	ld	a3,24(s10)
   11336:	855e                	mv	a0,s7
   11338:	85ca                	mv	a1,s2
   1133a:	864e                	mv	a2,s3
   1133c:	9682                	jalr	a3
   1133e:	85aa                	mv	a1,a0
   11340:	4505                	li	a0,1
   11342:	fdcd                	bnez	a1,112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>
   11344:	41900933          	neg	s2,s9
   11348:	59fd                	li	s3,-1
   1134a:	54fd                	li	s1,-1
   1134c:	00990533          	add	a0,s2,s1
   11350:	03350d63          	beq	a0,s3,1138a <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x21e>
   11354:	020d3603          	ld	a2,32(s10)
   11358:	855e                	mv	a0,s7
   1135a:	85e2                	mv	a1,s8
   1135c:	9602                	jalr	a2
   1135e:	0485                	addi	s1,s1,1
   11360:	d575                	beqz	a0,1134c <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x1e0>
   11362:	0194b533          	sltu	a0,s1,s9
   11366:	bf59                	j	112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>
   11368:	018d3683          	ld	a3,24(s10)
   1136c:	855e                	mv	a0,s7
   1136e:	85ca                	mv	a1,s2
   11370:	864e                	mv	a2,s3
   11372:	9682                	jalr	a3
   11374:	85aa                	mv	a1,a0
   11376:	4505                	li	a0,1
   11378:	f1d1                	bnez	a1,112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>
   1137a:	4501                	li	a0,0
   1137c:	034da823          	sw	s4,48(s11)
   11380:	f9043583          	ld	a1,-112(s0)
   11384:	02bd8c23          	sb	a1,56(s11)
   11388:	bf95                	j	112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>
   1138a:	019cb533          	sltu	a0,s9,s9
   1138e:	b7bd                	j	112fc <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E+0x190>

0000000000011390 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE>:
   11390:	7179                	addi	sp,sp,-48
   11392:	f406                	sd	ra,40(sp)
   11394:	f022                	sd	s0,32(sp)
   11396:	ec26                	sd	s1,24(sp)
   11398:	e84a                	sd	s2,16(sp)
   1139a:	e44e                	sd	s3,8(sp)
   1139c:	e052                	sd	s4,0(sp)
   1139e:	1800                	addi	s0,sp,48
   113a0:	0006079b          	sext.w	a5,a2
   113a4:	001104b7          	lui	s1,0x110
   113a8:	893a                	mv	s2,a4
   113aa:	8a36                	mv	s4,a3
   113ac:	89ae                	mv	s3,a1
   113ae:	00978b63          	beq	a5,s1,113c4 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE+0x34>
   113b2:	0209b683          	ld	a3,32(s3)
   113b6:	84aa                	mv	s1,a0
   113b8:	85b2                	mv	a1,a2
   113ba:	9682                	jalr	a3
   113bc:	862a                	mv	a2,a0
   113be:	8526                	mv	a0,s1
   113c0:	4585                	li	a1,1
   113c2:	e205                	bnez	a2,113e2 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE+0x52>
   113c4:	000a0e63          	beqz	s4,113e0 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17h6117598936567dedE+0x50>
   113c8:	0189b783          	ld	a5,24(s3)
   113cc:	85d2                	mv	a1,s4
   113ce:	864a                	mv	a2,s2
   113d0:	70a2                	ld	ra,40(sp)
   113d2:	7402                	ld	s0,32(sp)
   113d4:	64e2                	ld	s1,24(sp)
   113d6:	6942                	ld	s2,16(sp)
   113d8:	69a2                	ld	s3,8(sp)
   113da:	6a02                	ld	s4,0(sp)
   113dc:	6145                	addi	sp,sp,48
   113de:	8782                	jr	a5
   113e0:	4581                	li	a1,0
   113e2:	852e                	mv	a0,a1
   113e4:	70a2                	ld	ra,40(sp)
   113e6:	7402                	ld	s0,32(sp)
   113e8:	64e2                	ld	s1,24(sp)
   113ea:	6942                	ld	s2,16(sp)
   113ec:	69a2                	ld	s3,8(sp)
   113ee:	6a02                	ld	s4,0(sp)
   113f0:	6145                	addi	sp,sp,48
   113f2:	8082                	ret

00000000000113f4 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E>:
   113f4:	715d                	addi	sp,sp,-80
   113f6:	e486                	sd	ra,72(sp)
   113f8:	e0a2                	sd	s0,64(sp)
   113fa:	fc26                	sd	s1,56(sp)
   113fc:	f84a                	sd	s2,48(sp)
   113fe:	f44e                	sd	s3,40(sp)
   11400:	f052                	sd	s4,32(sp)
   11402:	ec56                	sd	s5,24(sp)
   11404:	e85a                	sd	s6,16(sp)
   11406:	e45e                	sd	s7,8(sp)
   11408:	0880                	addi	s0,sp,80
   1140a:	6114                	ld	a3,0(a0)
   1140c:	6918                	ld	a4,16(a0)
   1140e:	8932                	mv	s2,a2
   11410:	89ae                	mv	s3,a1
   11412:	00177593          	andi	a1,a4,1
   11416:	e291                	bnez	a3,1141a <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x26>
   11418:	cde5                	beqz	a1,11510 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x11c>
   1141a:	cdc1                	beqz	a1,114b2 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xbe>
   1141c:	6d18                	ld	a4,24(a0)
   1141e:	01298633          	add	a2,s3,s2
   11422:	4581                	li	a1,0
   11424:	c721                	beqz	a4,1146c <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x78>
   11426:	0e000893          	li	a7,224
   1142a:	0f000813          	li	a6,240
   1142e:	84ce                	mv	s1,s3
   11430:	a809                	j	11442 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x4e>
   11432:	00148793          	addi	a5,s1,1 # 110001 <_ZN8user_lib4HEAP17h79cac75b112c20f6E+0xf9001>
   11436:	8c8d                	sub	s1,s1,a1
   11438:	177d                	addi	a4,a4,-1
   1143a:	409785b3          	sub	a1,a5,s1
   1143e:	84be                	mv	s1,a5
   11440:	c71d                	beqz	a4,1146e <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x7a>
   11442:	06c48863          	beq	s1,a2,114b2 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xbe>
   11446:	00048783          	lb	a5,0(s1)
   1144a:	fe07d4e3          	bgez	a5,11432 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x3e>
   1144e:	0ff7f793          	andi	a5,a5,255
   11452:	0117e763          	bltu	a5,a7,11460 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x6c>
   11456:	0107e863          	bltu	a5,a6,11466 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x72>
   1145a:	00448793          	addi	a5,s1,4
   1145e:	bfe1                	j	11436 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x42>
   11460:	00248793          	addi	a5,s1,2
   11464:	bfc9                	j	11436 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x42>
   11466:	00348793          	addi	a5,s1,3
   1146a:	b7f1                	j	11436 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x42>
   1146c:	87ce                	mv	a5,s3
   1146e:	04c78263          	beq	a5,a2,114b2 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xbe>
   11472:	00078603          	lb	a2,0(a5)
   11476:	00064463          	bltz	a2,1147e <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x8a>
   1147a:	e599                	bnez	a1,11488 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x94>
   1147c:	a035                	j	114a8 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xb4>
   1147e:	0ff67613          	andi	a2,a2,255
   11482:	0e000713          	li	a4,224
   11486:	c18d                	beqz	a1,114a8 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xb4>
   11488:	0125fe63          	bgeu	a1,s2,114a4 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xb0>
   1148c:	00b98633          	add	a2,s3,a1
   11490:	00060603          	lb	a2,0(a2)
   11494:	fbf00713          	li	a4,-65
   11498:	00c74863          	blt	a4,a2,114a8 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xb4>
   1149c:	4601                	li	a2,0
   1149e:	00001863          	bnez	zero,114ae <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xba>
   114a2:	a801                	j	114b2 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xbe>
   114a4:	ff259ce3          	bne	a1,s2,1149c <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xa8>
   114a8:	864e                	mv	a2,s3
   114aa:	00098463          	beqz	s3,114b2 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xbe>
   114ae:	892e                	mv	s2,a1
   114b0:	89b2                	mv	s3,a2
   114b2:	ceb9                	beqz	a3,11510 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x11c>
   114b4:	6504                	ld	s1,8(a0)
   114b6:	02000593          	li	a1,32
   114ba:	04b97063          	bgeu	s2,a1,114fa <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x106>
   114be:	4581                	li	a1,0
   114c0:	00090f63          	beqz	s2,114de <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xea>
   114c4:	01298633          	add	a2,s3,s2
   114c8:	86ce                	mv	a3,s3
   114ca:	00068703          	lb	a4,0(a3)
   114ce:	fc072713          	slti	a4,a4,-64
   114d2:	00174713          	xori	a4,a4,1
   114d6:	0685                	addi	a3,a3,1
   114d8:	95ba                	add	a1,a1,a4
   114da:	fec698e3          	bne	a3,a2,114ca <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xd6>
   114de:	0295f963          	bgeu	a1,s1,11510 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x11c>
   114e2:	03854683          	lbu	a3,56(a0)
   114e6:	4601                	li	a2,0
   114e8:	4705                	li	a4,1
   114ea:	40b48ab3          	sub	s5,s1,a1
   114ee:	04d74163          	blt	a4,a3,11530 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x13c>
   114f2:	c6b9                	beqz	a3,11540 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x14c>
   114f4:	8656                	mv	a2,s5
   114f6:	4a81                	li	s5,0
   114f8:	a0a1                	j	11540 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x14c>
   114fa:	8a2a                	mv	s4,a0
   114fc:	854e                	mv	a0,s3
   114fe:	85ca                	mv	a1,s2
   11500:	00000097          	auipc	ra,0x0
   11504:	0e6080e7          	jalr	230(ra) # 115e6 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E>
   11508:	85aa                	mv	a1,a0
   1150a:	8552                	mv	a0,s4
   1150c:	fc95ebe3          	bltu	a1,s1,114e2 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0xee>
   11510:	750c                	ld	a1,40(a0)
   11512:	7108                	ld	a0,32(a0)
   11514:	6d9c                	ld	a5,24(a1)
   11516:	85ce                	mv	a1,s3
   11518:	864a                	mv	a2,s2
   1151a:	60a6                	ld	ra,72(sp)
   1151c:	6406                	ld	s0,64(sp)
   1151e:	74e2                	ld	s1,56(sp)
   11520:	7942                	ld	s2,48(sp)
   11522:	79a2                	ld	s3,40(sp)
   11524:	7a02                	ld	s4,32(sp)
   11526:	6ae2                	ld	s5,24(sp)
   11528:	6b42                	ld	s6,16(sp)
   1152a:	6ba2                	ld	s7,8(sp)
   1152c:	6161                	addi	sp,sp,80
   1152e:	8782                	jr	a5
   11530:	4589                	li	a1,2
   11532:	00b69763          	bne	a3,a1,11540 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x14c>
   11536:	001ad613          	srli	a2,s5,0x1
   1153a:	0a85                	addi	s5,s5,1
   1153c:	001ada93          	srli	s5,s5,0x1
   11540:	02053a03          	ld	s4,32(a0)
   11544:	02853b83          	ld	s7,40(a0)
   11548:	03052b03          	lw	s6,48(a0)
   1154c:	00160493          	addi	s1,a2,1
   11550:	14fd                	addi	s1,s1,-1
   11552:	c889                	beqz	s1,11564 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x170>
   11554:	020bb603          	ld	a2,32(s7)
   11558:	8552                	mv	a0,s4
   1155a:	85da                	mv	a1,s6
   1155c:	9602                	jalr	a2
   1155e:	d96d                	beqz	a0,11550 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x15c>
   11560:	4505                	li	a0,1
   11562:	a82d                	j	1159c <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x1a8>
   11564:	018bb683          	ld	a3,24(s7)
   11568:	8552                	mv	a0,s4
   1156a:	85ce                	mv	a1,s3
   1156c:	864a                	mv	a2,s2
   1156e:	9682                	jalr	a3
   11570:	85aa                	mv	a1,a0
   11572:	4505                	li	a0,1
   11574:	e585                	bnez	a1,1159c <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x1a8>
   11576:	41500933          	neg	s2,s5
   1157a:	59fd                	li	s3,-1
   1157c:	54fd                	li	s1,-1
   1157e:	00990533          	add	a0,s2,s1
   11582:	01350a63          	beq	a0,s3,11596 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x1a2>
   11586:	020bb603          	ld	a2,32(s7)
   1158a:	8552                	mv	a0,s4
   1158c:	85da                	mv	a1,s6
   1158e:	9602                	jalr	a2
   11590:	0485                	addi	s1,s1,1
   11592:	d575                	beqz	a0,1157e <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x18a>
   11594:	a011                	j	11598 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E+0x1a4>
   11596:	84d6                	mv	s1,s5
   11598:	0154b533          	sltu	a0,s1,s5
   1159c:	60a6                	ld	ra,72(sp)
   1159e:	6406                	ld	s0,64(sp)
   115a0:	74e2                	ld	s1,56(sp)
   115a2:	7942                	ld	s2,48(sp)
   115a4:	79a2                	ld	s3,40(sp)
   115a6:	7a02                	ld	s4,32(sp)
   115a8:	6ae2                	ld	s5,24(sp)
   115aa:	6b42                	ld	s6,16(sp)
   115ac:	6ba2                	ld	s7,8(sp)
   115ae:	6161                	addi	sp,sp,80
   115b0:	8082                	ret

00000000000115b2 <_ZN4core3fmt9Formatter9write_str17hb7ca0676c07ff6c7E>:
   115b2:	1141                	addi	sp,sp,-16
   115b4:	e406                	sd	ra,8(sp)
   115b6:	e022                	sd	s0,0(sp)
   115b8:	0800                	addi	s0,sp,16
   115ba:	7514                	ld	a3,40(a0)
   115bc:	7108                	ld	a0,32(a0)
   115be:	6e9c                	ld	a5,24(a3)
   115c0:	60a2                	ld	ra,8(sp)
   115c2:	6402                	ld	s0,0(sp)
   115c4:	0141                	addi	sp,sp,16
   115c6:	8782                	jr	a5

00000000000115c8 <_ZN42_$LT$str$u20$as$u20$core..fmt..Display$GT$3fmt17h621f2671cecc6bcaE>:
   115c8:	1141                	addi	sp,sp,-16
   115ca:	e406                	sd	ra,8(sp)
   115cc:	e022                	sd	s0,0(sp)
   115ce:	0800                	addi	s0,sp,16
   115d0:	86ae                	mv	a3,a1
   115d2:	85aa                	mv	a1,a0
   115d4:	8532                	mv	a0,a2
   115d6:	8636                	mv	a2,a3
   115d8:	60a2                	ld	ra,8(sp)
   115da:	6402                	ld	s0,0(sp)
   115dc:	0141                	addi	sp,sp,16
   115de:	00000317          	auipc	t1,0x0
   115e2:	e1630067          	jr	-490(t1) # 113f4 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E>

00000000000115e6 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E>:
   115e6:	1141                	addi	sp,sp,-16
   115e8:	e406                	sd	ra,8(sp)
   115ea:	e022                	sd	s0,0(sp)
   115ec:	0800                	addi	s0,sp,16
   115ee:	862a                	mv	a2,a0
   115f0:	00750793          	addi	a5,a0,7
   115f4:	9be1                	andi	a5,a5,-8
   115f6:	40a786b3          	sub	a3,a5,a0
   115fa:	12d5e163          	bltu	a1,a3,1171c <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x136>
   115fe:	40d58733          	sub	a4,a1,a3
   11602:	00375313          	srli	t1,a4,0x3
   11606:	10030b63          	beqz	t1,1171c <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x136>
   1160a:	96b2                	add	a3,a3,a2
   1160c:	00777813          	andi	a6,a4,7
   11610:	4501                	li	a0,0
   11612:	00c78c63          	beq	a5,a2,1162a <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x44>
   11616:	00060583          	lb	a1,0(a2)
   1161a:	fc05a593          	slti	a1,a1,-64
   1161e:	0015c593          	xori	a1,a1,1
   11622:	0605                	addi	a2,a2,1
   11624:	952e                	add	a0,a0,a1
   11626:	fed618e3          	bne	a2,a3,11616 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x30>
   1162a:	4601                	li	a2,0
   1162c:	02080263          	beqz	a6,11650 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x6a>
   11630:	ff877593          	andi	a1,a4,-8
   11634:	00b68733          	add	a4,a3,a1
   11638:	95be                	add	a1,a1,a5
   1163a:	95c2                	add	a1,a1,a6
   1163c:	00070783          	lb	a5,0(a4)
   11640:	fc07a793          	slti	a5,a5,-64
   11644:	0017c793          	xori	a5,a5,1
   11648:	0705                	addi	a4,a4,1
   1164a:	963e                	add	a2,a2,a5
   1164c:	feb718e3          	bne	a4,a1,1163c <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x56>
   11650:	010105b7          	lui	a1,0x1010
   11654:	1015859b          	addiw	a1,a1,257
   11658:	02059713          	slli	a4,a1,0x20
   1165c:	00e58fb3          	add	t6,a1,a4
   11660:	00ff0737          	lui	a4,0xff0
   11664:	0ff7089b          	addiw	a7,a4,255
   11668:	02089713          	slli	a4,a7,0x20
   1166c:	98ba                	add	a7,a7,a4
   1166e:	6741                	lui	a4,0x10
   11670:	2705                	addiw	a4,a4,1
   11672:	02071813          	slli	a6,a4,0x20
   11676:	983a                	add	a6,a6,a4
   11678:	9532                	add	a0,a0,a2
   1167a:	4291                	li	t0,4
   1167c:	a015                	j	116a0 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0xba>
   1167e:	006e06b3          	add	a3,t3,t1
   11682:	407e8333          	sub	t1,t4,t2
   11686:	0033f593          	andi	a1,t2,3
   1168a:	0117f633          	and	a2,a5,a7
   1168e:	83a1                	srli	a5,a5,0x8
   11690:	0117f733          	and	a4,a5,a7
   11694:	963a                	add	a2,a2,a4
   11696:	03060633          	mul	a2,a2,a6
   1169a:	9241                	srli	a2,a2,0x30
   1169c:	9532                	add	a0,a0,a2
   1169e:	e1c5                	bnez	a1,1173e <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x158>
   116a0:	08030b63          	beqz	t1,11736 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x150>
   116a4:	8e9a                	mv	t4,t1
   116a6:	8e36                	mv	t3,a3
   116a8:	0c000613          	li	a2,192
   116ac:	839a                	mv	t2,t1
   116ae:	00c36463          	bltu	t1,a2,116b6 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0xd0>
   116b2:	0c000393          	li	t2,192
   116b6:	00339313          	slli	t1,t2,0x3
   116ba:	4781                	li	a5,0
   116bc:	fc5ee1e3          	bltu	t4,t0,1167e <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x98>
   116c0:	7e037613          	andi	a2,t1,2016
   116c4:	00ce0f33          	add	t5,t3,a2
   116c8:	86f2                	mv	a3,t3
   116ca:	6298                	ld	a4,0(a3)
   116cc:	fff74613          	not	a2,a4
   116d0:	821d                	srli	a2,a2,0x7
   116d2:	8319                	srli	a4,a4,0x6
   116d4:	668c                	ld	a1,8(a3)
   116d6:	8e59                	or	a2,a2,a4
   116d8:	01f67633          	and	a2,a2,t6
   116dc:	963e                	add	a2,a2,a5
   116de:	fff5c713          	not	a4,a1
   116e2:	831d                	srli	a4,a4,0x7
   116e4:	6a9c                	ld	a5,16(a3)
   116e6:	8199                	srli	a1,a1,0x6
   116e8:	8dd9                	or	a1,a1,a4
   116ea:	01f5f5b3          	and	a1,a1,t6
   116ee:	fff7c713          	not	a4,a5
   116f2:	831d                	srli	a4,a4,0x7
   116f4:	8399                	srli	a5,a5,0x6
   116f6:	8f5d                	or	a4,a4,a5
   116f8:	6e9c                	ld	a5,24(a3)
   116fa:	01f77733          	and	a4,a4,t6
   116fe:	95ba                	add	a1,a1,a4
   11700:	95b2                	add	a1,a1,a2
   11702:	fff7c613          	not	a2,a5
   11706:	821d                	srli	a2,a2,0x7
   11708:	8399                	srli	a5,a5,0x6
   1170a:	8e5d                	or	a2,a2,a5
   1170c:	01f677b3          	and	a5,a2,t6
   11710:	02068693          	addi	a3,a3,32
   11714:	97ae                	add	a5,a5,a1
   11716:	fbe69ae3          	bne	a3,t5,116ca <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0xe4>
   1171a:	b795                	j	1167e <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x98>
   1171c:	4501                	li	a0,0
   1171e:	cd81                	beqz	a1,11736 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x150>
   11720:	95b2                	add	a1,a1,a2
   11722:	00060683          	lb	a3,0(a2)
   11726:	fc06a693          	slti	a3,a3,-64
   1172a:	0016c693          	xori	a3,a3,1
   1172e:	0605                	addi	a2,a2,1
   11730:	9536                	add	a0,a0,a3
   11732:	feb618e3          	bne	a2,a1,11722 <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x13c>
   11736:	60a2                	ld	ra,8(sp)
   11738:	6402                	ld	s0,0(sp)
   1173a:	0141                	addi	sp,sp,16
   1173c:	8082                	ret
   1173e:	4601                	li	a2,0
   11740:	0fc3f593          	andi	a1,t2,252
   11744:	058e                	slli	a1,a1,0x3
   11746:	9e2e                	add	t3,t3,a1
   11748:	0c0eb593          	sltiu	a1,t4,192
   1174c:	40b005bb          	negw	a1,a1
   11750:	00bef5b3          	and	a1,t4,a1
   11754:	898d                	andi	a1,a1,3
   11756:	00359693          	slli	a3,a1,0x3
   1175a:	000e3583          	ld	a1,0(t3)
   1175e:	0e21                	addi	t3,t3,8
   11760:	fff5c713          	not	a4,a1
   11764:	831d                	srli	a4,a4,0x7
   11766:	8199                	srli	a1,a1,0x6
   11768:	8dd9                	or	a1,a1,a4
   1176a:	01f5f5b3          	and	a1,a1,t6
   1176e:	16e1                	addi	a3,a3,-8
   11770:	962e                	add	a2,a2,a1
   11772:	f6e5                	bnez	a3,1175a <_ZN4core3str5count14do_count_chars17ha3587c73edcca475E+0x174>
   11774:	011675b3          	and	a1,a2,a7
   11778:	8221                	srli	a2,a2,0x8
   1177a:	01167633          	and	a2,a2,a7
   1177e:	95b2                	add	a1,a1,a2
   11780:	030585b3          	mul	a1,a1,a6
   11784:	91c1                	srli	a1,a1,0x30
   11786:	952e                	add	a0,a0,a1
   11788:	60a2                	ld	ra,8(sp)
   1178a:	6402                	ld	s0,0(sp)
   1178c:	0141                	addi	sp,sp,16
   1178e:	8082                	ret

0000000000011790 <_ZN4core3fmt3num3imp7fmt_u6417h7d856a578ab2dde7E>:
   11790:	715d                	addi	sp,sp,-80
   11792:	e486                	sd	ra,72(sp)
   11794:	e0a2                	sd	s0,64(sp)
   11796:	fc26                	sd	s1,56(sp)
   11798:	f84a                	sd	s2,48(sp)
   1179a:	0880                	addi	s0,sp,80
   1179c:	8832                	mv	a6,a2
   1179e:	00455693          	srli	a3,a0,0x4
   117a2:	02700713          	li	a4,39
   117a6:	27100793          	li	a5,625

00000000000117aa <.Lpcrel_hi922>:
   117aa:	00001617          	auipc	a2,0x1
   117ae:	e1e60e93          	addi	t4,a2,-482 # 125c8 <.Lanon.10f909bc3d7870a0109061ce2530e04d.291>
   117b2:	02f6f363          	bgeu	a3,a5,117d8 <.Lpcrel_hi922+0x2e>
   117b6:	06300693          	li	a3,99
   117ba:	0aa6ea63          	bltu	a3,a0,1186e <.Lpcrel_hi923+0x8c>
   117be:	4629                	li	a2,10
   117c0:	0ec57863          	bgeu	a0,a2,118b0 <.Lpcrel_hi923+0xce>
   117c4:	fff70693          	addi	a3,a4,-1 # ffff <$d+0xffa1>
   117c8:	fb940613          	addi	a2,s0,-71
   117cc:	9636                	add	a2,a2,a3
   117ce:	03056513          	ori	a0,a0,48
   117d2:	00a60023          	sb	a0,0(a2)
   117d6:	a8e5                	j	118ce <.Lpcrel_hi923+0xec>
   117d8:	4701                	li	a4,0
   117da:	fdc40893          	addi	a7,s0,-36
   117de:	fde40293          	addi	t0,s0,-34

00000000000117e2 <.Lpcrel_hi923>:
   117e2:	00001697          	auipc	a3,0x1
   117e6:	86e6b303          	ld	t1,-1938(a3) # 12050 <.Lanon.fad58de7366495db4650cfefac2fcd61.3+0x30>
   117ea:	6689                	lui	a3,0x2
   117ec:	71068e13          	addi	t3,a3,1808 # 2710 <$d+0x26b2>
   117f0:	6685                	lui	a3,0x1
   117f2:	47b68f1b          	addiw	t5,a3,1147
   117f6:	06400393          	li	t2,100
   117fa:	05f5e6b7          	lui	a3,0x5f5e
   117fe:	0ff68f9b          	addiw	t6,a3,255
   11802:	892a                	mv	s2,a0
   11804:	02653533          	mulhu	a0,a0,t1
   11808:	812d                	srli	a0,a0,0xb
   1180a:	03c507b3          	mul	a5,a0,t3
   1180e:	40f9063b          	subw	a2,s2,a5
   11812:	03061793          	slli	a5,a2,0x30
   11816:	93c9                	srli	a5,a5,0x32
   11818:	03e787b3          	mul	a5,a5,t5
   1181c:	0117d493          	srli	s1,a5,0x11
   11820:	83c1                	srli	a5,a5,0x10
   11822:	7fe7f793          	andi	a5,a5,2046
   11826:	027484b3          	mul	s1,s1,t2
   1182a:	9e05                	subw	a2,a2,s1
   1182c:	1646                	slli	a2,a2,0x31
   1182e:	97f6                	add	a5,a5,t4
   11830:	0017c483          	lbu	s1,1(a5)
   11834:	9241                	srli	a2,a2,0x30
   11836:	00e886b3          	add	a3,a7,a4
   1183a:	0007c783          	lbu	a5,0(a5)
   1183e:	009680a3          	sb	s1,1(a3) # 5f5e001 <_ZN8user_lib4HEAP17h79cac75b112c20f6E+0x5f47001>
   11842:	9676                	add	a2,a2,t4
   11844:	00164483          	lbu	s1,1(a2)
   11848:	00064603          	lbu	a2,0(a2)
   1184c:	00f68023          	sb	a5,0(a3)
   11850:	00e286b3          	add	a3,t0,a4
   11854:	009680a3          	sb	s1,1(a3)
   11858:	00c68023          	sb	a2,0(a3)
   1185c:	1771                	addi	a4,a4,-4
   1185e:	fb2fe2e3          	bltu	t6,s2,11802 <.Lpcrel_hi923+0x20>
   11862:	02770713          	addi	a4,a4,39
   11866:	06300693          	li	a3,99
   1186a:	f4a6fae3          	bgeu	a3,a0,117be <.Lpcrel_hi922+0x14>
   1186e:	03051613          	slli	a2,a0,0x30
   11872:	9249                	srli	a2,a2,0x32
   11874:	6685                	lui	a3,0x1
   11876:	47b6869b          	addiw	a3,a3,1147
   1187a:	02d60633          	mul	a2,a2,a3
   1187e:	8245                	srli	a2,a2,0x11
   11880:	06400693          	li	a3,100
   11884:	02d606b3          	mul	a3,a2,a3
   11888:	9d15                	subw	a0,a0,a3
   1188a:	1546                	slli	a0,a0,0x31
   1188c:	9141                	srli	a0,a0,0x30
   1188e:	1779                	addi	a4,a4,-2
   11890:	9576                	add	a0,a0,t4
   11892:	00154683          	lbu	a3,1(a0)
   11896:	00054503          	lbu	a0,0(a0)
   1189a:	fb940793          	addi	a5,s0,-71
   1189e:	97ba                	add	a5,a5,a4
   118a0:	00d780a3          	sb	a3,1(a5)
   118a4:	00a78023          	sb	a0,0(a5)
   118a8:	8532                	mv	a0,a2
   118aa:	4629                	li	a2,10
   118ac:	f0c56ce3          	bltu	a0,a2,117c4 <.Lpcrel_hi922+0x1a>
   118b0:	0506                	slli	a0,a0,0x1
   118b2:	ffe70693          	addi	a3,a4,-2
   118b6:	9576                	add	a0,a0,t4
   118b8:	00154603          	lbu	a2,1(a0)
   118bc:	00054503          	lbu	a0,0(a0)
   118c0:	fb940713          	addi	a4,s0,-71
   118c4:	9736                	add	a4,a4,a3
   118c6:	00c700a3          	sb	a2,1(a4)
   118ca:	00a70023          	sb	a0,0(a4)
   118ce:	fb940713          	addi	a4,s0,-71
   118d2:	9736                	add	a4,a4,a3
   118d4:	02700793          	li	a5,39
   118d8:	8f95                	sub	a5,a5,a3
   118da:	4605                	li	a2,1
   118dc:	8542                	mv	a0,a6
   118de:	4681                	li	a3,0
   118e0:	00000097          	auipc	ra,0x0
   118e4:	88c080e7          	jalr	-1908(ra) # 1116c <_ZN4core3fmt9Formatter12pad_integral17h984f78a6748856d4E>
   118e8:	60a6                	ld	ra,72(sp)
   118ea:	6406                	ld	s0,64(sp)
   118ec:	74e2                	ld	s1,56(sp)
   118ee:	7942                	ld	s2,48(sp)
   118f0:	6161                	addi	sp,sp,80
   118f2:	8082                	ret

00000000000118f4 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$3fmt17h55bc9281ebd53aceE>:
   118f4:	1141                	addi	sp,sp,-16
   118f6:	e406                	sd	ra,8(sp)
   118f8:	e022                	sd	s0,0(sp)
   118fa:	0800                	addi	s0,sp,16
   118fc:	00056503          	lwu	a0,0(a0)
   11900:	862e                	mv	a2,a1
   11902:	4585                	li	a1,1
   11904:	60a2                	ld	ra,8(sp)
   11906:	6402                	ld	s0,0(sp)
   11908:	0141                	addi	sp,sp,16
   1190a:	00000317          	auipc	t1,0x0
   1190e:	e8630067          	jr	-378(t1) # 11790 <_ZN4core3fmt3num3imp7fmt_u6417h7d856a578ab2dde7E>

0000000000011912 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$i64$GT$3fmt17hc54d1578b1a353a6E>:
   11912:	1141                	addi	sp,sp,-16
   11914:	e406                	sd	ra,8(sp)
   11916:	e022                	sd	s0,0(sp)
   11918:	0800                	addi	s0,sp,16
   1191a:	6110                	ld	a2,0(a0)
   1191c:	43f65513          	srai	a0,a2,0x3f
   11920:	00a646b3          	xor	a3,a2,a0
   11924:	40a68533          	sub	a0,a3,a0
   11928:	fff64613          	not	a2,a2
   1192c:	927d                	srli	a2,a2,0x3f
   1192e:	86ae                	mv	a3,a1
   11930:	85b2                	mv	a1,a2
   11932:	8636                	mv	a2,a3
   11934:	60a2                	ld	ra,8(sp)
   11936:	6402                	ld	s0,0(sp)
   11938:	0141                	addi	sp,sp,16
   1193a:	00000317          	auipc	t1,0x0
   1193e:	e5630067          	jr	-426(t1) # 11790 <_ZN4core3fmt3num3imp7fmt_u6417h7d856a578ab2dde7E>

0000000000011942 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u64$GT$3fmt17hbebc74f197ec876aE>:
   11942:	1141                	addi	sp,sp,-16
   11944:	e406                	sd	ra,8(sp)
   11946:	e022                	sd	s0,0(sp)
   11948:	0800                	addi	s0,sp,16
   1194a:	6108                	ld	a0,0(a0)
   1194c:	862e                	mv	a2,a1
   1194e:	4585                	li	a1,1
   11950:	60a2                	ld	ra,8(sp)
   11952:	6402                	ld	s0,0(sp)
   11954:	0141                	addi	sp,sp,16
   11956:	00000317          	auipc	t1,0x0
   1195a:	e3a30067          	jr	-454(t1) # 11790 <_ZN4core3fmt3num3imp7fmt_u6417h7d856a578ab2dde7E>

000000000001195e <_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17ha805f7b075431583E>:
   1195e:	1141                	addi	sp,sp,-16
   11960:	e406                	sd	ra,8(sp)
   11962:	e022                	sd	s0,0(sp)
   11964:	0800                	addi	s0,sp,16
   11966:	6510                	ld	a2,8(a0)
   11968:	6108                	ld	a0,0(a0)
   1196a:	6e1c                	ld	a5,24(a2)
   1196c:	60a2                	ld	ra,8(sp)
   1196e:	6402                	ld	s0,0(sp)
   11970:	0141                	addi	sp,sp,16
   11972:	8782                	jr	a5

0000000000011974 <_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h2e1e8d2633c3d1cfE>:
   11974:	1141                	addi	sp,sp,-16
   11976:	e406                	sd	ra,8(sp)
   11978:	e022                	sd	s0,0(sp)
   1197a:	0800                	addi	s0,sp,16
   1197c:	6114                	ld	a3,0(a0)
   1197e:	6510                	ld	a2,8(a0)
   11980:	852e                	mv	a0,a1
   11982:	85b6                	mv	a1,a3
   11984:	60a2                	ld	ra,8(sp)
   11986:	6402                	ld	s0,0(sp)
   11988:	0141                	addi	sp,sp,16
   1198a:	00000317          	auipc	t1,0x0
   1198e:	a6a30067          	jr	-1430(t1) # 113f4 <_ZN4core3fmt9Formatter3pad17h0932de2772ed71a7E>

0000000000011992 <memcpy>:
   11992:	1141                	addi	sp,sp,-16
   11994:	e406                	sd	ra,8(sp)
   11996:	e022                	sd	s0,0(sp)
   11998:	0800                	addi	s0,sp,16
   1199a:	46c1                	li	a3,16
   1199c:	06d66b63          	bltu	a2,a3,11a12 <memcpy+0x80>
   119a0:	40a006bb          	negw	a3,a0
   119a4:	0076f813          	andi	a6,a3,7
   119a8:	010503b3          	add	t2,a0,a6
   119ac:	00080c63          	beqz	a6,119c4 <memcpy+0x32>
   119b0:	87aa                	mv	a5,a0
   119b2:	86ae                	mv	a3,a1
   119b4:	0006c703          	lbu	a4,0(a3) # 1000 <$d+0xfa2>
   119b8:	00e78023          	sb	a4,0(a5)
   119bc:	0785                	addi	a5,a5,1
   119be:	0685                	addi	a3,a3,1
   119c0:	fe77eae3          	bltu	a5,t2,119b4 <memcpy+0x22>
   119c4:	010588b3          	add	a7,a1,a6
   119c8:	41060833          	sub	a6,a2,a6
   119cc:	ff887293          	andi	t0,a6,-8
   119d0:	0078f593          	andi	a1,a7,7
   119d4:	005386b3          	add	a3,t2,t0
   119d8:	c1a1                	beqz	a1,11a18 <memcpy+0x86>
   119da:	04505963          	blez	t0,11a2c <memcpy+0x9a>
   119de:	00389593          	slli	a1,a7,0x3
   119e2:	0385f313          	andi	t1,a1,56
   119e6:	ff88f793          	andi	a5,a7,-8
   119ea:	6390                	ld	a2,0(a5)
   119ec:	40b005bb          	negw	a1,a1
   119f0:	0385fe13          	andi	t3,a1,56
   119f4:	07a1                	addi	a5,a5,8
   119f6:	6398                	ld	a4,0(a5)
   119f8:	00665633          	srl	a2,a2,t1
   119fc:	01c715b3          	sll	a1,a4,t3
   11a00:	8dd1                	or	a1,a1,a2
   11a02:	00b3b023          	sd	a1,0(t2)
   11a06:	03a1                	addi	t2,t2,8
   11a08:	07a1                	addi	a5,a5,8
   11a0a:	863a                	mv	a2,a4
   11a0c:	fed3e5e3          	bltu	t2,a3,119f6 <memcpy+0x64>
   11a10:	a831                	j	11a2c <memcpy+0x9a>
   11a12:	86aa                	mv	a3,a0
   11a14:	e20d                	bnez	a2,11a36 <memcpy+0xa4>
   11a16:	a80d                	j	11a48 <memcpy+0xb6>
   11a18:	00505a63          	blez	t0,11a2c <memcpy+0x9a>
   11a1c:	85c6                	mv	a1,a7
   11a1e:	6190                	ld	a2,0(a1)
   11a20:	00c3b023          	sd	a2,0(t2)
   11a24:	03a1                	addi	t2,t2,8
   11a26:	05a1                	addi	a1,a1,8
   11a28:	fed3ebe3          	bltu	t2,a3,11a1e <memcpy+0x8c>
   11a2c:	005885b3          	add	a1,a7,t0
   11a30:	00787613          	andi	a2,a6,7
   11a34:	ca11                	beqz	a2,11a48 <memcpy+0xb6>
   11a36:	9636                	add	a2,a2,a3
   11a38:	0005c703          	lbu	a4,0(a1) # 1010000 <_ZN8user_lib4HEAP17h79cac75b112c20f6E+0xff9000>
   11a3c:	00e68023          	sb	a4,0(a3)
   11a40:	0685                	addi	a3,a3,1
   11a42:	0585                	addi	a1,a1,1
   11a44:	fec6eae3          	bltu	a3,a2,11a38 <memcpy+0xa6>
   11a48:	60a2                	ld	ra,8(sp)
   11a4a:	6402                	ld	s0,0(sp)
   11a4c:	0141                	addi	sp,sp,16
   11a4e:	8082                	ret

0000000000011a50 <memset>:
   11a50:	1141                	addi	sp,sp,-16
   11a52:	e406                	sd	ra,8(sp)
   11a54:	e022                	sd	s0,0(sp)
   11a56:	0800                	addi	s0,sp,16
   11a58:	46c1                	li	a3,16
   11a5a:	04d66a63          	bltu	a2,a3,11aae <memset+0x5e>
   11a5e:	40a006bb          	negw	a3,a0
   11a62:	8a9d                	andi	a3,a3,7
   11a64:	00d50733          	add	a4,a0,a3
   11a68:	c699                	beqz	a3,11a76 <memset+0x26>
   11a6a:	87aa                	mv	a5,a0
   11a6c:	00b78023          	sb	a1,0(a5)
   11a70:	0785                	addi	a5,a5,1
   11a72:	fee7ede3          	bltu	a5,a4,11a6c <memset+0x1c>
   11a76:	40d608b3          	sub	a7,a2,a3
   11a7a:	ff88f793          	andi	a5,a7,-8
   11a7e:	00f706b3          	add	a3,a4,a5
   11a82:	02f05263          	blez	a5,11aa6 <memset+0x56>
   11a86:	03859813          	slli	a6,a1,0x38
   11a8a:	101017b7          	lui	a5,0x10101
   11a8e:	0792                	slli	a5,a5,0x4
   11a90:	10078793          	addi	a5,a5,256 # 10101100 <_ZN8user_lib4HEAP17h79cac75b112c20f6E+0x100ea100>
   11a94:	02f83633          	mulhu	a2,a6,a5
   11a98:	02061793          	slli	a5,a2,0x20
   11a9c:	8fd1                	or	a5,a5,a2
   11a9e:	e31c                	sd	a5,0(a4)
   11aa0:	0721                	addi	a4,a4,8
   11aa2:	fed76ee3          	bltu	a4,a3,11a9e <memset+0x4e>
   11aa6:	0078f613          	andi	a2,a7,7
   11aaa:	e601                	bnez	a2,11ab2 <memset+0x62>
   11aac:	a809                	j	11abe <memset+0x6e>
   11aae:	86aa                	mv	a3,a0
   11ab0:	c619                	beqz	a2,11abe <memset+0x6e>
   11ab2:	9636                	add	a2,a2,a3
   11ab4:	00b68023          	sb	a1,0(a3)
   11ab8:	0685                	addi	a3,a3,1
   11aba:	fec6ede3          	bltu	a3,a2,11ab4 <memset+0x64>
   11abe:	60a2                	ld	ra,8(sp)
   11ac0:	6402                	ld	s0,0(sp)
   11ac2:	0141                	addi	sp,sp,16
   11ac4:	8082                	ret
