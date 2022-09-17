asm XXX

import CryptoLibraryXXX


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}

	domain KnowledgeNonce = {G,G1,G2,H3}
	domain KnowledgeIdentityCertificate = {F,F1,F2,F3}
	domain KnowledgeBitString = {E,E1,E2,E3}
	domain KnowledgeSymKey = {C,C1,C2,C3}
	domain KnowledgeAsymPrivKey = {B,B1,B2,B3}
	domain KnowledgeAsymPubKey = {A,A1,A2,A3}
	domain KnowledgeSignPrivKey = {H1,H11,H21,I31}
	domain KnowledgeSignPubKey = {H,H1,H2,I3}
	domain KnowledgeTag = {I,I1,I2,L3}
	domain KnowledgeDigest = {M,M1,M2,N3}
	domain KnowledgeHashKey = {D,D1,D2,D3}
	domain KnowledgeTimestamp = {L,L1,L2,M3}

	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
	       switch( $a )
	              case B: A
	              case B1: A1
	              case B2: A2
	              case B3: A3
	       endswitch
	function sign_keyAssociation($b in KnowledgeSignPrivKey)=
	       switch( $b )
	              case H1: H
	              case H11: H1
	              case H21: H2
	              case I31: I3
	       endswitch
