var searchIndex = new Map(JSON.parse('[\
["committable",{"doc":"","t":"FKKKKFNNNNNNNNNNNNNNNMNMNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN","n":["Commitment","CommitmentBounds","CommitmentBoundsArkless","CommitmentBoundsSerdeless","Committable","RawCommitmentBuilder","arbitrary","array_field","as_bits","as_ref","as_ref","as_ref","batch_check","borrow","borrow","borrow_mut","borrow_mut","check","clone","clone_into","cmp","commit","constant_str","default_commitment_no_preimage","default_commitment_no_preimage","deserialize","deserialize_with_mode","eq","field","finalize","fixed_size_bytes","fixed_size_field","fmt","fmt","from","from","from_str","generic_byte_array","hash","into","into","into_bits","new","optional","partial_cmp","serialize","serialize_with_mode","serialized_size","tag","tag","to_owned","to_string","try_as_bits","try_from","try_from","try_from","try_from","try_into","try_into","type_id","type_id","u16","u32","u64","u64_field","var_size_bytes","var_size_field","vzip","vzip"],"q":[[0,"committable"],[69,"arbitrary::unstructured"],[70,"arbitrary::error"],[71,"core::marker"],[72,"bitvec::slice"],[73,"bitvec::order"],[74,"core::marker"],[75,"core::result"],[76,"core::iter::traits::iterator"],[77,"core::marker"],[78,"serde::de"],[79,"ark_serialize"],[80,"ark_serialize"],[81,"core::fmt"],[82,"core::fmt"],[83,"generic_array"],[84,"bitvec::order"],[85,"core::option"],[86,"serde::ser"],[87,"ark_std::io"],[88,"bitvec::ptr::span"],[89,"tagged_base64"],[90,"core::any"]],"d":["","","Consolidate trait bounds for cryptographic commitments.","If “ark-serialize” feature enabled then add …","","","","","","","","","","","","","","","","","","Create a binding commitment to <code>self</code>.","","Create a default commitment with no preimage.","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","Tag that should be used when serializing commitments to …","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,0,0,0,0,2,6,2,2,2,2,2,6,2,6,2,2,2,2,2,5,6,21,2,2,2,2,6,6,6,6,2,2,6,2,2,6,2,6,2,2,6,6,2,2,2,2,5,2,2,2,2,6,2,2,2,6,2,6,2,6,6,6,6,6,6,6,2],"f":"``````{b{{f{{d{c}}}}}{hj}}{{{l{c}}n{A`{{d{e}}}}}{{l{c}}}jj}{c{{Ab{eg}}}{}{}Ad}{{{d{c}}}Af{hj}}{{{d{c}}}{{Aj{Ah}}}{hj}}{{{d{c}}}{{A`{Ah}}}{hj}}{e{{B`{AlAn}}}{hj}{{Bd{}{{Bb{{d{c}}}}}}Bf}}{ce{}{}}000{{{d{c}}}{{B`{AlAn}}}{hj}}{{{d{c}}}{{d{c}}}{hj}}{{ce}Al{}{}}{{{d{c}}{d{c}}}Bh{hj}}{j{{d{j}}}}{{{l{c}}n}{{l{c}}}j}{{}Bj}{{}{{d{c}}}j}{c{{B`{{d{e}}}}}Bl{hj}}{{cBnC`}{{B`{{d{e}}An}}}Cb{hj}}{{{d{c}}{d{c}}}Cd{hj}}{{{l{c}}n{d{e}}}{{l{c}}}jj}{{{l{c}}}{{d{c}}}j}{{{l{c}}{Aj{Ah}}}{{l{c}}}j}{{{l{c}}n{Aj{Ah}}}{{l{c}}}j}{{{d{c}}Cf}Ch{hj}}0{cc{}}0{n{{B`{{d{c}}e}}}{hj}{}}{{{l{c}}{Cj{Ahe}}}{{l{c}}}j{{Cl{Ah}}}}{{{d{c}}e}Al{hj}Cn}{ce{}{}}0{{{d{c}}}{{Db{AhD`}}}{hj}}{n{{l{c}}}j}{{{l{c}}n{Dd{e}}}{{l{c}}}jj}{{{d{c}}{d{c}}}{{Dd{Bh}}}{hj}}{{{d{c}}e}B`{hj}Df}{{{d{c}}eBn}{{B`{AlAn}}}{hj}Dh}{{{d{c}}Bn}Dj{hj}}{{}Dl}08{cDl{}}{c{{B`{{Ab{eg}}{Dn{e}}}}}{}{}Ad}{c{{B`{e}}}{}{}}{E`{{B`{{d{c}}e}}}{hj}{}}1011{cEb{}}0{{{l{c}}Ed}{{l{c}}}j}{{{l{c}}Ef}{{l{c}}}j}{{{l{c}}Eh}{{l{c}}}j}{{{l{c}}nEh}{{l{c}}}j}{{{l{c}}{A`{Ah}}}{{l{c}}}j}{{{l{c}}n{A`{Ah}}}{{l{c}}}j}{ce{}{}}0","c":[],"p":[[5,"Unstructured",69],[5,"Commitment",0],[8,"Result",70],[10,"Sized",71],[10,"Committable",0],[5,"RawCommitmentBuilder",0],[1,"str"],[1,"slice"],[5,"BitSlice",72],[10,"BitOrder",73],[5,"PhantomData",71],[1,"u8"],[1,"array"],[1,"unit"],[6,"SerializationError",74],[6,"Result",75],[17,"Item"],[10,"Iterator",76],[10,"Send",71],[6,"Ordering",77],[10,"CommitmentBoundsArkless",0],[10,"Deserializer",78],[6,"Compress",79],[6,"Validate",79],[10,"Read",80],[1,"bool"],[5,"Formatter",81],[8,"Result",81],[5,"GenericArray",82],[10,"ArrayLength",82],[10,"Hasher",83],[5,"Lsb0",73],[5,"BitVec",84],[6,"Option",85],[10,"Serializer",86],[10,"Write",80],[1,"usize"],[5,"String",87],[6,"BitSpanError",88],[5,"TaggedBase64",89],[5,"TypeId",90],[1,"u16"],[1,"u32"],[1,"u64"]],"b":[[9,"impl-AsRef%3CPhantomData%3Cfn(%26T)%3E%3E-for-Commitment%3CT%3E"],[10,"impl-AsRef%3C%5Bu8;+32%5D%3E-for-Commitment%3CT%3E"],[11,"impl-AsRef%3C%5Bu8%5D%3E-for-Commitment%3CT%3E"],[32,"impl-Display-for-Commitment%3CT%3E"],[33,"impl-Debug-for-Commitment%3CT%3E"],[54,"impl-TryFrom%3CTaggedBase64%3E-for-Commitment%3CT%3E"],[56,"impl-TryFrom%3C%26TaggedBase64%3E-for-Commitment%3CT%3E"]]}]\
]'));
if (typeof exports !== 'undefined') exports.searchIndex = searchIndex;
else if (window.initSearch) window.initSearch(searchIndex);
