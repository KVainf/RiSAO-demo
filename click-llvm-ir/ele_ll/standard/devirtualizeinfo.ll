; ModuleID = '../elements/standard/devirtualizeinfo.cc'
source_filename = "../elements/standard/devirtualizeinfo.cc"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%class.DevirtualizeInfo = type { %class.Element.base, [4 x i8] }
%class.Element.base = type <{ i32 (...)**, [2 x %"class.Element::Port"*], [4 x %"class.Element::Port"], [2 x i32], %class.Router*, i32 }>
%"class.Element::Port" = type <{ %class.Element*, i32, [4 x i8] }>
%class.Element = type <{ i32 (...)**, [2 x %"class.Element::Port"*], [4 x %"class.Element::Port"], [2 x i32], %class.Router*, i32, [4 x i8] }>
%class.Router = type opaque
%class.Vector = type opaque
%class.ErrorHandler = type opaque
%class.Packet = type { %class.atomic_uint32_t, %class.Packet*, i8*, i8*, i8*, i8*, %"struct.Packet::AllAnno", void (i8*, i64, i8*)*, i8* }
%class.atomic_uint32_t = type { i32 }
%"struct.Packet::AllAnno" = type { %"union.Packet::Anno", i8*, i8*, i8*, i32, [8 x i8], %class.Packet*, %class.Packet* }
%"union.Packet::Anno" = type { [6 x i64] }
%class.Task = type opaque
%class.Timer = type opaque
%class.String = type { %"struct.String::rep_t" }
%"struct.String::rep_t" = type { i8*, i32, %"struct.String::memo_t"* }
%"struct.String::memo_t" = type { i32, i32, i32, [8 x i8] }

$_ZN16DevirtualizeInfoD0Ev = comdat any

$_ZNK16DevirtualizeInfo10class_nameEv = comdat any

@_ZTV16DevirtualizeInfo = dso_local unnamed_addr constant { [29 x i8*] } { [29 x i8*] [i8* null, i8* bitcast ({ i8*, i8*, i8* }* @_ZTI16DevirtualizeInfo to i8*), i8* bitcast (void (%class.Element*)* @_ZN7ElementD2Ev to i8*), i8* bitcast (void (%class.DevirtualizeInfo*)* @_ZN16DevirtualizeInfoD0Ev to i8*), i8* bitcast (void (%class.Element*, i32, %class.Packet*)* @_ZN7Element4pushEiP6Packet to i8*), i8* bitcast (%class.Packet* (%class.Element*, i32)* @_ZN7Element4pullEi to i8*), i8* bitcast (%class.Packet* (%class.Element*, %class.Packet*)* @_ZN7Element13simple_actionEP6Packet to i8*), i8* bitcast (i1 (%class.Element*, %class.Task*)* @_ZN7Element8run_taskEP4Task to i8*), i8* bitcast (void (%class.Element*, %class.Timer*)* @_ZN7Element9run_timerEP5Timer to i8*), i8* bitcast (void (%class.Element*, i32, i32)* @_ZN7Element8selectedEii to i8*), i8* bitcast (void (%class.Element*, i32)* @_ZN7Element8selectedEi to i8*), i8* bitcast (i8* (%class.DevirtualizeInfo*)* @_ZNK16DevirtualizeInfo10class_nameEv to i8*), i8* bitcast (i8* (%class.Element*)* @_ZNK7Element10port_countEv to i8*), i8* bitcast (i8* (%class.Element*)* @_ZNK7Element10processingEv to i8*), i8* bitcast (i8* (%class.Element*)* @_ZNK7Element9flow_codeEv to i8*), i8* bitcast (i8* (%class.Element*)* @_ZNK7Element5flagsEv to i8*), i8* bitcast (i8* (%class.Element*, i8*)* @_ZN7Element4castEPKc to i8*), i8* bitcast (i8* (%class.Element*, i1, i32, i8*)* @_ZN7Element9port_castEbiPKc to i8*), i8* bitcast (i32 (%class.Element*)* @_ZNK7Element15configure_phaseEv to i8*), i8* bitcast (i32 (%class.DevirtualizeInfo*, %class.Vector*, %class.ErrorHandler*)* @_ZN16DevirtualizeInfo9configureER6VectorI6StringEP12ErrorHandler to i8*), i8* bitcast (void (%class.Element*)* @_ZN7Element12add_handlersEv to i8*), i8* bitcast (i32 (%class.Element*, %class.ErrorHandler*)* @_ZN7Element10initializeEP12ErrorHandler to i8*), i8* bitcast (void (%class.Element*, %class.Element*, %class.ErrorHandler*)* @_ZN7Element10take_stateEPS_P12ErrorHandler to i8*), i8* bitcast (%class.Element* (%class.Element*)* @_ZNK7Element15hotswap_elementEv to i8*), i8* bitcast (void (%class.Element*, i32)* @_ZN7Element7cleanupENS_12CleanupStageE to i8*), i8* bitcast (void (%class.String*, %class.Element*)* @_ZNK7Element11declarationEv to i8*), i8* bitcast (i1 (%class.Element*)* @_ZNK7Element20can_live_reconfigureEv to i8*), i8* bitcast (i32 (%class.Element*, %class.Vector*, %class.ErrorHandler*)* @_ZN7Element16live_reconfigureER6VectorI6StringEP12ErrorHandler to i8*), i8* bitcast (i32 (%class.Element*, i32, i8*)* @_ZN7Element5llrpcEjPv to i8*)] }, align 8
@_ZTVN10__cxxabiv120__si_class_type_infoE = external global i8*
@_ZTS16DevirtualizeInfo = dso_local constant [19 x i8] c"16DevirtualizeInfo\00", align 1
@_ZTI7Element = external constant i8*
@_ZTI16DevirtualizeInfo = dso_local constant { i8*, i8*, i8* } { i8* bitcast (i8** getelementptr inbounds (i8*, i8** @_ZTVN10__cxxabiv120__si_class_type_infoE, i64 2) to i8*), i8* getelementptr inbounds ([19 x i8], [19 x i8]* @_ZTS16DevirtualizeInfo, i32 0, i32 0), i8* bitcast (i8** @_ZTI7Element to i8*) }, align 8
@.str = private unnamed_addr constant [17 x i8] c"DevirtualizeInfo\00", align 1

@_ZN16DevirtualizeInfoC1Ev = dso_local unnamed_addr alias void (%class.DevirtualizeInfo*), void (%class.DevirtualizeInfo*)* @_ZN16DevirtualizeInfoC2Ev

; Function Attrs: sspstrong uwtable
define dso_local void @_ZN16DevirtualizeInfoC2Ev(%class.DevirtualizeInfo* %0) unnamed_addr #0 align 2 !dbg !653 {
  call void @llvm.dbg.value(metadata %class.DevirtualizeInfo* %0, metadata !679, metadata !DIExpression()), !dbg !681
  %2 = bitcast %class.DevirtualizeInfo* %0 to %class.Element*, !dbg !682
  tail call void @_ZN7ElementC2Ev(%class.Element* %2), !dbg !683
  %3 = getelementptr %class.DevirtualizeInfo, %class.DevirtualizeInfo* %0, i64 0, i32 0, i32 0, !dbg !682
  store i32 (...)** bitcast (i8** getelementptr inbounds ({ [29 x i8*] }, { [29 x i8*] }* @_ZTV16DevirtualizeInfo, i64 0, inrange i32 0, i64 2) to i32 (...)**), i32 (...)*** %3, align 8, !dbg !682, !tbaa !684
  ret void, !dbg !687
}

declare void @_ZN7ElementC2Ev(%class.Element*) unnamed_addr #1

; Function Attrs: norecurse nounwind readnone sspstrong uwtable
define dso_local i32 @_ZN16DevirtualizeInfo9configureER6VectorI6StringEP12ErrorHandler(%class.DevirtualizeInfo* nocapture readnone %0, %class.Vector* nocapture nonnull readnone %1, %class.ErrorHandler* nocapture readnone %2) unnamed_addr #2 align 2 !dbg !688 {
  call void @llvm.dbg.value(metadata %class.DevirtualizeInfo* undef, metadata !690, metadata !DIExpression()), !dbg !693
  call void @llvm.dbg.value(metadata %class.Vector* undef, metadata !691, metadata !DIExpression()), !dbg !693
  call void @llvm.dbg.value(metadata %class.ErrorHandler* undef, metadata !692, metadata !DIExpression()), !dbg !693
  ret i32 0, !dbg !694
}

; Function Attrs: nounwind
declare void @_ZN7ElementD2Ev(%class.Element*) unnamed_addr #3

; Function Attrs: inlinehint nounwind sspstrong uwtable
define linkonce_odr dso_local void @_ZN16DevirtualizeInfoD0Ev(%class.DevirtualizeInfo* %0) unnamed_addr #4 comdat align 2 !dbg !695 {
  call void @llvm.dbg.value(metadata %class.DevirtualizeInfo* %0, metadata !698, metadata !DIExpression()), !dbg !699
  %2 = bitcast %class.DevirtualizeInfo* %0 to %class.Element*, !dbg !700
  tail call void @_ZN7ElementD2Ev(%class.Element* %2) #8, !dbg !700
  %3 = bitcast %class.DevirtualizeInfo* %0 to i8*, !dbg !700
  tail call void @_ZdlPv(i8* %3) #9, !dbg !700
  ret void, !dbg !700
}

declare void @_ZN7Element4pushEiP6Packet(%class.Element*, i32, %class.Packet*) unnamed_addr #1

declare %class.Packet* @_ZN7Element4pullEi(%class.Element*, i32) unnamed_addr #1

declare %class.Packet* @_ZN7Element13simple_actionEP6Packet(%class.Element*, %class.Packet*) unnamed_addr #1

declare zeroext i1 @_ZN7Element8run_taskEP4Task(%class.Element*, %class.Task*) unnamed_addr #1

declare void @_ZN7Element9run_timerEP5Timer(%class.Element*, %class.Timer*) unnamed_addr #1

declare void @_ZN7Element8selectedEii(%class.Element*, i32, i32) unnamed_addr #1

declare void @_ZN7Element8selectedEi(%class.Element*, i32) unnamed_addr #1

; Function Attrs: nounwind sspstrong uwtable
define linkonce_odr dso_local i8* @_ZNK16DevirtualizeInfo10class_nameEv(%class.DevirtualizeInfo* %0) unnamed_addr #5 comdat align 2 !dbg !701 {
  call void @llvm.dbg.value(metadata %class.DevirtualizeInfo* %0, metadata !703, metadata !DIExpression()), !dbg !705
  ret i8* getelementptr inbounds ([17 x i8], [17 x i8]* @.str, i64 0, i64 0), !dbg !706
}

declare i8* @_ZNK7Element10port_countEv(%class.Element*) unnamed_addr #1

declare i8* @_ZNK7Element10processingEv(%class.Element*) unnamed_addr #1

declare i8* @_ZNK7Element9flow_codeEv(%class.Element*) unnamed_addr #1

declare i8* @_ZNK7Element5flagsEv(%class.Element*) unnamed_addr #1

declare i8* @_ZN7Element4castEPKc(%class.Element*, i8*) unnamed_addr #1

declare i8* @_ZN7Element9port_castEbiPKc(%class.Element*, i1 zeroext, i32, i8*) unnamed_addr #1

declare i32 @_ZNK7Element15configure_phaseEv(%class.Element*) unnamed_addr #1

declare void @_ZN7Element12add_handlersEv(%class.Element*) unnamed_addr #1

declare i32 @_ZN7Element10initializeEP12ErrorHandler(%class.Element*, %class.ErrorHandler*) unnamed_addr #1

declare void @_ZN7Element10take_stateEPS_P12ErrorHandler(%class.Element*, %class.Element*, %class.ErrorHandler*) unnamed_addr #1

declare %class.Element* @_ZNK7Element15hotswap_elementEv(%class.Element*) unnamed_addr #1

declare void @_ZN7Element7cleanupENS_12CleanupStageE(%class.Element*, i32) unnamed_addr #1

declare void @_ZNK7Element11declarationEv(%class.String* sret, %class.Element*) unnamed_addr #1

declare zeroext i1 @_ZNK7Element20can_live_reconfigureEv(%class.Element*) unnamed_addr #1

declare i32 @_ZN7Element16live_reconfigureER6VectorI6StringEP12ErrorHandler(%class.Element*, %class.Vector* nonnull, %class.ErrorHandler*) unnamed_addr #1

declare i32 @_ZN7Element5llrpcEjPv(%class.Element*, i32, i8*) unnamed_addr #1

; Function Attrs: nobuiltin nounwind
declare void @_ZdlPv(i8*) local_unnamed_addr #6

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #7

attributes #0 = { sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { norecurse nounwind readnone sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { inlinehint nounwind sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { nounwind sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #6 = { nobuiltin nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #7 = { nounwind readnone speculatable willreturn }
attributes #8 = { nounwind }
attributes #9 = { builtin nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!647, !648, !649, !650, !651}
!llvm.ident = !{!652}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !1, producer: "clang version 10.0.0 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, imports: !3, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "../elements/standard/devirtualizeinfo.cc", directory: "/home/john/projects/click/ir-dir")
!2 = !{}
!3 = !{!4, !62, !66, !73, !77, !84, !88, !93, !95, !104, !108, !112, !126, !130, !134, !138, !142, !147, !151, !155, !159, !163, !171, !175, !179, !181, !185, !189, !194, !200, !204, !208, !210, !218, !222, !230, !232, !236, !240, !244, !248, !253, !258, !263, !264, !265, !266, !268, !269, !270, !271, !272, !273, !274, !276, !277, !278, !279, !280, !281, !282, !287, !288, !289, !290, !291, !292, !293, !294, !295, !296, !297, !298, !299, !300, !301, !302, !303, !304, !305, !306, !307, !308, !309, !310, !311, !317, !319, !321, !325, !327, !329, !331, !333, !335, !337, !339, !344, !348, !350, !352, !357, !359, !361, !363, !365, !367, !369, !372, !374, !376, !380, !384, !386, !388, !390, !392, !394, !396, !398, !400, !402, !404, !408, !412, !414, !416, !418, !420, !422, !424, !426, !428, !430, !432, !434, !436, !438, !440, !442, !446, !450, !454, !456, !458, !460, !462, !464, !466, !468, !470, !472, !476, !480, !484, !486, !488, !490, !494, !498, !502, !504, !506, !508, !510, !512, !514, !516, !518, !520, !522, !524, !526, !530, !534, !538, !540, !542, !544, !546, !550, !554, !556, !558, !560, !562, !564, !566, !570, !574, !576, !578, !580, !582, !586, !590, !594, !596, !598, !600, !602, !604, !606, !610, !614, !618, !620, !624, !628, !630, !632, !634, !636, !638, !640, !642}
!4 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !6, file: !7, line: 58)
!5 = !DINamespace(name: "std", scope: null)
!6 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "exception_ptr", scope: !8, file: !7, line: 80, size: 64, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !9, identifier: "_ZTSNSt15__exception_ptr13exception_ptrE")
!7 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/bits/exception_ptr.h", directory: "")
!8 = !DINamespace(name: "__exception_ptr", scope: !5)
!9 = !{!10, !12, !16, !19, !20, !25, !26, !30, !36, !40, !44, !47, !48, !51, !55}
!10 = !DIDerivedType(tag: DW_TAG_member, name: "_M_exception_object", scope: !6, file: !7, line: 82, baseType: !11, size: 64)
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!12 = !DISubprogram(name: "exception_ptr", scope: !6, file: !7, line: 84, type: !13, scopeLine: 84, flags: DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!13 = !DISubroutineType(types: !14)
!14 = !{null, !15, !11}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!16 = !DISubprogram(name: "_M_addref", linkageName: "_ZNSt15__exception_ptr13exception_ptr9_M_addrefEv", scope: !6, file: !7, line: 86, type: !17, scopeLine: 86, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!17 = !DISubroutineType(types: !18)
!18 = !{null, !15}
!19 = !DISubprogram(name: "_M_release", linkageName: "_ZNSt15__exception_ptr13exception_ptr10_M_releaseEv", scope: !6, file: !7, line: 87, type: !17, scopeLine: 87, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!20 = !DISubprogram(name: "_M_get", linkageName: "_ZNKSt15__exception_ptr13exception_ptr6_M_getEv", scope: !6, file: !7, line: 89, type: !21, scopeLine: 89, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!21 = !DISubroutineType(types: !22)
!22 = !{!11, !23}
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!24 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !6)
!25 = !DISubprogram(name: "exception_ptr", scope: !6, file: !7, line: 97, type: !17, scopeLine: 97, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!26 = !DISubprogram(name: "exception_ptr", scope: !6, file: !7, line: 99, type: !27, scopeLine: 99, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!27 = !DISubroutineType(types: !28)
!28 = !{null, !15, !29}
!29 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !24, size: 64)
!30 = !DISubprogram(name: "exception_ptr", scope: !6, file: !7, line: 102, type: !31, scopeLine: 102, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!31 = !DISubroutineType(types: !32)
!32 = !{null, !15, !33}
!33 = !DIDerivedType(tag: DW_TAG_typedef, name: "nullptr_t", scope: !5, file: !34, line: 264, baseType: !35)
!34 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/x86_64-pc-linux-gnu/bits/c++config.h", directory: "")
!35 = !DIBasicType(tag: DW_TAG_unspecified_type, name: "decltype(nullptr)")
!36 = !DISubprogram(name: "exception_ptr", scope: !6, file: !7, line: 106, type: !37, scopeLine: 106, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!37 = !DISubroutineType(types: !38)
!38 = !{null, !15, !39}
!39 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !6, size: 64)
!40 = !DISubprogram(name: "operator=", linkageName: "_ZNSt15__exception_ptr13exception_ptraSERKS0_", scope: !6, file: !7, line: 119, type: !41, scopeLine: 119, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!41 = !DISubroutineType(types: !42)
!42 = !{!43, !15, !29}
!43 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !6, size: 64)
!44 = !DISubprogram(name: "operator=", linkageName: "_ZNSt15__exception_ptr13exception_ptraSEOS0_", scope: !6, file: !7, line: 123, type: !45, scopeLine: 123, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!45 = !DISubroutineType(types: !46)
!46 = !{!43, !15, !39}
!47 = !DISubprogram(name: "~exception_ptr", scope: !6, file: !7, line: 130, type: !17, scopeLine: 130, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!48 = !DISubprogram(name: "swap", linkageName: "_ZNSt15__exception_ptr13exception_ptr4swapERS0_", scope: !6, file: !7, line: 133, type: !49, scopeLine: 133, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!49 = !DISubroutineType(types: !50)
!50 = !{null, !15, !43}
!51 = !DISubprogram(name: "operator bool", linkageName: "_ZNKSt15__exception_ptr13exception_ptrcvbEv", scope: !6, file: !7, line: 145, type: !52, scopeLine: 145, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!52 = !DISubroutineType(types: !53)
!53 = !{!54, !23}
!54 = !DIBasicType(name: "bool", size: 8, encoding: DW_ATE_boolean)
!55 = !DISubprogram(name: "__cxa_exception_type", linkageName: "_ZNKSt15__exception_ptr13exception_ptr20__cxa_exception_typeEv", scope: !6, file: !7, line: 154, type: !56, scopeLine: 154, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!56 = !DISubroutineType(types: !57)
!57 = !{!58, !23}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !60)
!60 = !DICompositeType(tag: DW_TAG_class_type, name: "type_info", scope: !5, file: !61, line: 88, flags: DIFlagFwdDecl, identifier: "_ZTSSt9type_info")
!61 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/typeinfo", directory: "")
!62 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !8, entity: !63, file: !7, line: 74)
!63 = !DISubprogram(name: "rethrow_exception", linkageName: "_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE", scope: !5, file: !7, line: 70, type: !64, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!64 = !DISubroutineType(types: !65)
!65 = !{null, !6}
!66 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !67, file: !72, line: 52)
!67 = !DISubprogram(name: "abs", scope: !68, file: !68, line: 840, type: !69, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!68 = !DIFile(filename: "/usr/include/stdlib.h", directory: "")
!69 = !DISubroutineType(types: !70)
!70 = !{!71, !71}
!71 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!72 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/bits/std_abs.h", directory: "")
!73 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !74, file: !76, line: 127)
!74 = !DIDerivedType(tag: DW_TAG_typedef, name: "div_t", file: !68, line: 62, baseType: !75)
!75 = !DICompositeType(tag: DW_TAG_structure_type, file: !68, line: 58, flags: DIFlagFwdDecl, identifier: "_ZTS5div_t")
!76 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/cstdlib", directory: "")
!77 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !78, file: !76, line: 128)
!78 = !DIDerivedType(tag: DW_TAG_typedef, name: "ldiv_t", file: !68, line: 70, baseType: !79)
!79 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !68, line: 66, size: 128, flags: DIFlagTypePassByValue, elements: !80, identifier: "_ZTS6ldiv_t")
!80 = !{!81, !83}
!81 = !DIDerivedType(tag: DW_TAG_member, name: "quot", scope: !79, file: !68, line: 68, baseType: !82, size: 64)
!82 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!83 = !DIDerivedType(tag: DW_TAG_member, name: "rem", scope: !79, file: !68, line: 69, baseType: !82, size: 64, offset: 64)
!84 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !85, file: !76, line: 130)
!85 = !DISubprogram(name: "abort", scope: !68, file: !68, line: 591, type: !86, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!86 = !DISubroutineType(types: !87)
!87 = !{null}
!88 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !89, file: !76, line: 134)
!89 = !DISubprogram(name: "atexit", scope: !68, file: !68, line: 595, type: !90, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!90 = !DISubroutineType(types: !91)
!91 = !{!71, !92}
!92 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !86, size: 64)
!93 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !94, file: !76, line: 137)
!94 = !DISubprogram(name: "at_quick_exit", scope: !68, file: !68, line: 600, type: !90, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!95 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !96, file: !76, line: 140)
!96 = !DISubprogram(name: "atof", scope: !97, file: !97, line: 25, type: !98, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!97 = !DIFile(filename: "/usr/include/bits/stdlib-float.h", directory: "")
!98 = !DISubroutineType(types: !99)
!99 = !{!100, !101}
!100 = !DIBasicType(name: "double", size: 64, encoding: DW_ATE_float)
!101 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !102, size: 64)
!102 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !103)
!103 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!104 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !105, file: !76, line: 141)
!105 = !DISubprogram(name: "atoi", scope: !68, file: !68, line: 361, type: !106, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!106 = !DISubroutineType(types: !107)
!107 = !{!71, !101}
!108 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !109, file: !76, line: 142)
!109 = !DISubprogram(name: "atol", scope: !68, file: !68, line: 366, type: !110, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!110 = !DISubroutineType(types: !111)
!111 = !{!82, !101}
!112 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !113, file: !76, line: 143)
!113 = !DISubprogram(name: "bsearch", scope: !114, file: !114, line: 20, type: !115, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!114 = !DIFile(filename: "/usr/include/bits/stdlib-bsearch.h", directory: "")
!115 = !DISubroutineType(types: !116)
!116 = !{!11, !117, !117, !119, !119, !122}
!117 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !118, size: 64)
!118 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!119 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !120, line: 46, baseType: !121)
!120 = !DIFile(filename: "/usr/lib/clang/10.0.0/include/stddef.h", directory: "")
!121 = !DIBasicType(name: "long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!122 = !DIDerivedType(tag: DW_TAG_typedef, name: "__compar_fn_t", file: !68, line: 808, baseType: !123)
!123 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !124, size: 64)
!124 = !DISubroutineType(types: !125)
!125 = !{!71, !117, !117}
!126 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !127, file: !76, line: 144)
!127 = !DISubprogram(name: "calloc", scope: !68, file: !68, line: 542, type: !128, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!128 = !DISubroutineType(types: !129)
!129 = !{!11, !119, !119}
!130 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !131, file: !76, line: 145)
!131 = !DISubprogram(name: "div", scope: !68, file: !68, line: 852, type: !132, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!132 = !DISubroutineType(types: !133)
!133 = !{!74, !71, !71}
!134 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !135, file: !76, line: 146)
!135 = !DISubprogram(name: "exit", scope: !68, file: !68, line: 617, type: !136, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!136 = !DISubroutineType(types: !137)
!137 = !{null, !71}
!138 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !139, file: !76, line: 147)
!139 = !DISubprogram(name: "free", scope: !68, file: !68, line: 565, type: !140, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!140 = !DISubroutineType(types: !141)
!141 = !{null, !11}
!142 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !143, file: !76, line: 148)
!143 = !DISubprogram(name: "getenv", scope: !68, file: !68, line: 634, type: !144, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!144 = !DISubroutineType(types: !145)
!145 = !{!146, !101}
!146 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !103, size: 64)
!147 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !148, file: !76, line: 149)
!148 = !DISubprogram(name: "labs", scope: !68, file: !68, line: 841, type: !149, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!149 = !DISubroutineType(types: !150)
!150 = !{!82, !82}
!151 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !152, file: !76, line: 150)
!152 = !DISubprogram(name: "ldiv", scope: !68, file: !68, line: 854, type: !153, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!153 = !DISubroutineType(types: !154)
!154 = !{!78, !82, !82}
!155 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !156, file: !76, line: 151)
!156 = !DISubprogram(name: "malloc", scope: !68, file: !68, line: 539, type: !157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!157 = !DISubroutineType(types: !158)
!158 = !{!11, !119}
!159 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !160, file: !76, line: 153)
!160 = !DISubprogram(name: "mblen", scope: !68, file: !68, line: 922, type: !161, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!161 = !DISubroutineType(types: !162)
!162 = !{!71, !101, !119}
!163 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !164, file: !76, line: 154)
!164 = !DISubprogram(name: "mbstowcs", scope: !68, file: !68, line: 933, type: !165, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!165 = !DISubroutineType(types: !166)
!166 = !{!119, !167, !170, !119}
!167 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !168)
!168 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !169, size: 64)
!169 = !DIBasicType(name: "wchar_t", size: 32, encoding: DW_ATE_signed)
!170 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !101)
!171 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !172, file: !76, line: 155)
!172 = !DISubprogram(name: "mbtowc", scope: !68, file: !68, line: 925, type: !173, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!173 = !DISubroutineType(types: !174)
!174 = !{!71, !167, !170, !119}
!175 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !176, file: !76, line: 157)
!176 = !DISubprogram(name: "qsort", scope: !68, file: !68, line: 830, type: !177, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!177 = !DISubroutineType(types: !178)
!178 = !{null, !11, !119, !119, !122}
!179 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !180, file: !76, line: 160)
!180 = !DISubprogram(name: "quick_exit", scope: !68, file: !68, line: 623, type: !136, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!181 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !182, file: !76, line: 163)
!182 = !DISubprogram(name: "rand", scope: !68, file: !68, line: 453, type: !183, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!183 = !DISubroutineType(types: !184)
!184 = !{!71}
!185 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !186, file: !76, line: 164)
!186 = !DISubprogram(name: "realloc", scope: !68, file: !68, line: 550, type: !187, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!187 = !DISubroutineType(types: !188)
!188 = !{!11, !11, !119}
!189 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !190, file: !76, line: 165)
!190 = !DISubprogram(name: "srand", scope: !68, file: !68, line: 455, type: !191, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!191 = !DISubroutineType(types: !192)
!192 = !{null, !193}
!193 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!194 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !195, file: !76, line: 166)
!195 = !DISubprogram(name: "strtod", scope: !68, file: !68, line: 117, type: !196, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!196 = !DISubroutineType(types: !197)
!197 = !{!100, !170, !198}
!198 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !199)
!199 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !146, size: 64)
!200 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !201, file: !76, line: 167)
!201 = !DISubprogram(name: "strtol", scope: !68, file: !68, line: 176, type: !202, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!202 = !DISubroutineType(types: !203)
!203 = !{!82, !170, !198, !71}
!204 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !205, file: !76, line: 168)
!205 = !DISubprogram(name: "strtoul", scope: !68, file: !68, line: 180, type: !206, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!206 = !DISubroutineType(types: !207)
!207 = !{!121, !170, !198, !71}
!208 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !209, file: !76, line: 169)
!209 = !DISubprogram(name: "system", scope: !68, file: !68, line: 784, type: !106, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!210 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !211, file: !76, line: 171)
!211 = !DISubprogram(name: "wcstombs", scope: !68, file: !68, line: 936, type: !212, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!212 = !DISubroutineType(types: !213)
!213 = !{!119, !214, !215, !119}
!214 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !146)
!215 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !216)
!216 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !217, size: 64)
!217 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !169)
!218 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !219, file: !76, line: 172)
!219 = !DISubprogram(name: "wctomb", scope: !68, file: !68, line: 929, type: !220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!220 = !DISubroutineType(types: !221)
!221 = !{!71, !146, !169}
!222 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !224, file: !76, line: 200)
!223 = !DINamespace(name: "__gnu_cxx", scope: null)
!224 = !DIDerivedType(tag: DW_TAG_typedef, name: "lldiv_t", file: !68, line: 80, baseType: !225)
!225 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !68, line: 76, size: 128, flags: DIFlagTypePassByValue, elements: !226, identifier: "_ZTS7lldiv_t")
!226 = !{!227, !229}
!227 = !DIDerivedType(tag: DW_TAG_member, name: "quot", scope: !225, file: !68, line: 78, baseType: !228, size: 64)
!228 = !DIBasicType(name: "long long int", size: 64, encoding: DW_ATE_signed)
!229 = !DIDerivedType(tag: DW_TAG_member, name: "rem", scope: !225, file: !68, line: 79, baseType: !228, size: 64, offset: 64)
!230 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !231, file: !76, line: 206)
!231 = !DISubprogram(name: "_Exit", scope: !68, file: !68, line: 629, type: !136, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!232 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !233, file: !76, line: 210)
!233 = !DISubprogram(name: "llabs", scope: !68, file: !68, line: 844, type: !234, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!234 = !DISubroutineType(types: !235)
!235 = !{!228, !228}
!236 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !237, file: !76, line: 216)
!237 = !DISubprogram(name: "lldiv", scope: !68, file: !68, line: 858, type: !238, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!238 = !DISubroutineType(types: !239)
!239 = !{!224, !228, !228}
!240 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !241, file: !76, line: 227)
!241 = !DISubprogram(name: "atoll", scope: !68, file: !68, line: 373, type: !242, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!242 = !DISubroutineType(types: !243)
!243 = !{!228, !101}
!244 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !245, file: !76, line: 228)
!245 = !DISubprogram(name: "strtoll", scope: !68, file: !68, line: 200, type: !246, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!246 = !DISubroutineType(types: !247)
!247 = !{!228, !170, !198, !71}
!248 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !249, file: !76, line: 229)
!249 = !DISubprogram(name: "strtoull", scope: !68, file: !68, line: 205, type: !250, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!250 = !DISubroutineType(types: !251)
!251 = !{!252, !170, !198, !71}
!252 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!253 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !254, file: !76, line: 231)
!254 = !DISubprogram(name: "strtof", scope: !68, file: !68, line: 123, type: !255, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!255 = !DISubroutineType(types: !256)
!256 = !{!257, !170, !198}
!257 = !DIBasicType(name: "float", size: 32, encoding: DW_ATE_float)
!258 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !223, entity: !259, file: !76, line: 232)
!259 = !DISubprogram(name: "strtold", scope: !68, file: !68, line: 126, type: !260, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!260 = !DISubroutineType(types: !261)
!261 = !{!262, !170, !198}
!262 = !DIBasicType(name: "long double", size: 128, encoding: DW_ATE_float)
!263 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !224, file: !76, line: 240)
!264 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !231, file: !76, line: 242)
!265 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !233, file: !76, line: 244)
!266 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !267, file: !76, line: 245)
!267 = !DISubprogram(name: "div", linkageName: "_ZN9__gnu_cxx3divExx", scope: !223, file: !76, line: 213, type: !238, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!268 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !237, file: !76, line: 246)
!269 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !241, file: !76, line: 248)
!270 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !254, file: !76, line: 249)
!271 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !245, file: !76, line: 250)
!272 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !249, file: !76, line: 251)
!273 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !259, file: !76, line: 252)
!274 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !85, file: !275, line: 38)
!275 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/stdlib.h", directory: "")
!276 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !89, file: !275, line: 39)
!277 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !135, file: !275, line: 40)
!278 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !94, file: !275, line: 43)
!279 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !180, file: !275, line: 46)
!280 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !74, file: !275, line: 51)
!281 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !78, file: !275, line: 52)
!282 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !283, file: !275, line: 54)
!283 = !DISubprogram(name: "abs", linkageName: "_ZSt3absg", scope: !5, file: !72, line: 103, type: !284, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!284 = !DISubroutineType(types: !285)
!285 = !{!286, !286}
!286 = !DIBasicType(name: "__float128", size: 128, encoding: DW_ATE_float)
!287 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !96, file: !275, line: 55)
!288 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !105, file: !275, line: 56)
!289 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !109, file: !275, line: 57)
!290 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !113, file: !275, line: 58)
!291 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !127, file: !275, line: 59)
!292 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !267, file: !275, line: 60)
!293 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !139, file: !275, line: 61)
!294 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !143, file: !275, line: 62)
!295 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !148, file: !275, line: 63)
!296 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !152, file: !275, line: 64)
!297 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !156, file: !275, line: 65)
!298 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !160, file: !275, line: 67)
!299 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !164, file: !275, line: 68)
!300 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !172, file: !275, line: 69)
!301 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !176, file: !275, line: 71)
!302 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !182, file: !275, line: 72)
!303 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !186, file: !275, line: 73)
!304 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !190, file: !275, line: 74)
!305 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !195, file: !275, line: 75)
!306 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !201, file: !275, line: 76)
!307 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !205, file: !275, line: 77)
!308 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !209, file: !275, line: 78)
!309 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !211, file: !275, line: 80)
!310 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !219, file: !275, line: 81)
!311 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !312, file: !316, line: 83)
!312 = !DISubprogram(name: "acos", scope: !313, file: !313, line: 53, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!313 = !DIFile(filename: "/usr/include/bits/mathcalls.h", directory: "")
!314 = !DISubroutineType(types: !315)
!315 = !{!100, !100}
!316 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/cmath", directory: "")
!317 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !318, file: !316, line: 102)
!318 = !DISubprogram(name: "asin", scope: !313, file: !313, line: 55, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!319 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !320, file: !316, line: 121)
!320 = !DISubprogram(name: "atan", scope: !313, file: !313, line: 57, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!321 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !322, file: !316, line: 140)
!322 = !DISubprogram(name: "atan2", scope: !313, file: !313, line: 59, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!323 = !DISubroutineType(types: !324)
!324 = !{!100, !100, !100}
!325 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !326, file: !316, line: 161)
!326 = !DISubprogram(name: "ceil", scope: !313, file: !313, line: 159, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!327 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !328, file: !316, line: 180)
!328 = !DISubprogram(name: "cos", scope: !313, file: !313, line: 62, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!329 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !330, file: !316, line: 199)
!330 = !DISubprogram(name: "cosh", scope: !313, file: !313, line: 71, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!331 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !332, file: !316, line: 218)
!332 = !DISubprogram(name: "exp", scope: !313, file: !313, line: 95, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!333 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !334, file: !316, line: 237)
!334 = !DISubprogram(name: "fabs", scope: !313, file: !313, line: 162, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!335 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !336, file: !316, line: 256)
!336 = !DISubprogram(name: "floor", scope: !313, file: !313, line: 165, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!337 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !338, file: !316, line: 275)
!338 = !DISubprogram(name: "fmod", scope: !313, file: !313, line: 168, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!339 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !340, file: !316, line: 296)
!340 = !DISubprogram(name: "frexp", scope: !313, file: !313, line: 98, type: !341, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!341 = !DISubroutineType(types: !342)
!342 = !{!100, !100, !343}
!343 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !71, size: 64)
!344 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !345, file: !316, line: 315)
!345 = !DISubprogram(name: "ldexp", scope: !313, file: !313, line: 101, type: !346, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!346 = !DISubroutineType(types: !347)
!347 = !{!100, !100, !71}
!348 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !349, file: !316, line: 334)
!349 = !DISubprogram(name: "log", scope: !313, file: !313, line: 104, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!350 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !351, file: !316, line: 353)
!351 = !DISubprogram(name: "log10", scope: !313, file: !313, line: 107, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!352 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !353, file: !316, line: 372)
!353 = !DISubprogram(name: "modf", scope: !313, file: !313, line: 110, type: !354, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!354 = !DISubroutineType(types: !355)
!355 = !{!100, !100, !356}
!356 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !100, size: 64)
!357 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !358, file: !316, line: 384)
!358 = !DISubprogram(name: "pow", scope: !313, file: !313, line: 140, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!359 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !360, file: !316, line: 421)
!360 = !DISubprogram(name: "sin", scope: !313, file: !313, line: 64, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!361 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !362, file: !316, line: 440)
!362 = !DISubprogram(name: "sinh", scope: !313, file: !313, line: 73, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!363 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !364, file: !316, line: 459)
!364 = !DISubprogram(name: "sqrt", scope: !313, file: !313, line: 143, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!365 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !366, file: !316, line: 478)
!366 = !DISubprogram(name: "tan", scope: !313, file: !313, line: 66, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!367 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !368, file: !316, line: 497)
!368 = !DISubprogram(name: "tanh", scope: !313, file: !313, line: 75, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!369 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !370, file: !316, line: 1065)
!370 = !DIDerivedType(tag: DW_TAG_typedef, name: "double_t", file: !371, line: 150, baseType: !100)
!371 = !DIFile(filename: "/usr/include/math.h", directory: "")
!372 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !373, file: !316, line: 1066)
!373 = !DIDerivedType(tag: DW_TAG_typedef, name: "float_t", file: !371, line: 149, baseType: !257)
!374 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !375, file: !316, line: 1069)
!375 = !DISubprogram(name: "acosh", scope: !313, file: !313, line: 85, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!376 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !377, file: !316, line: 1070)
!377 = !DISubprogram(name: "acoshf", scope: !313, file: !313, line: 85, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!378 = !DISubroutineType(types: !379)
!379 = !{!257, !257}
!380 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !381, file: !316, line: 1071)
!381 = !DISubprogram(name: "acoshl", scope: !313, file: !313, line: 85, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!382 = !DISubroutineType(types: !383)
!383 = !{!262, !262}
!384 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !385, file: !316, line: 1073)
!385 = !DISubprogram(name: "asinh", scope: !313, file: !313, line: 87, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!386 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !387, file: !316, line: 1074)
!387 = !DISubprogram(name: "asinhf", scope: !313, file: !313, line: 87, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!388 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !389, file: !316, line: 1075)
!389 = !DISubprogram(name: "asinhl", scope: !313, file: !313, line: 87, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!390 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !391, file: !316, line: 1077)
!391 = !DISubprogram(name: "atanh", scope: !313, file: !313, line: 89, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!392 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !393, file: !316, line: 1078)
!393 = !DISubprogram(name: "atanhf", scope: !313, file: !313, line: 89, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!394 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !395, file: !316, line: 1079)
!395 = !DISubprogram(name: "atanhl", scope: !313, file: !313, line: 89, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!396 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !397, file: !316, line: 1081)
!397 = !DISubprogram(name: "cbrt", scope: !313, file: !313, line: 152, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!398 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !399, file: !316, line: 1082)
!399 = !DISubprogram(name: "cbrtf", scope: !313, file: !313, line: 152, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!400 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !401, file: !316, line: 1083)
!401 = !DISubprogram(name: "cbrtl", scope: !313, file: !313, line: 152, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!402 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !403, file: !316, line: 1085)
!403 = !DISubprogram(name: "copysign", scope: !313, file: !313, line: 196, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!404 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !405, file: !316, line: 1086)
!405 = !DISubprogram(name: "copysignf", scope: !313, file: !313, line: 196, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!406 = !DISubroutineType(types: !407)
!407 = !{!257, !257, !257}
!408 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !409, file: !316, line: 1087)
!409 = !DISubprogram(name: "copysignl", scope: !313, file: !313, line: 196, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!410 = !DISubroutineType(types: !411)
!411 = !{!262, !262, !262}
!412 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !413, file: !316, line: 1089)
!413 = !DISubprogram(name: "erf", scope: !313, file: !313, line: 228, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!414 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !415, file: !316, line: 1090)
!415 = !DISubprogram(name: "erff", scope: !313, file: !313, line: 228, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!416 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !417, file: !316, line: 1091)
!417 = !DISubprogram(name: "erfl", scope: !313, file: !313, line: 228, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!418 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !419, file: !316, line: 1093)
!419 = !DISubprogram(name: "erfc", scope: !313, file: !313, line: 229, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!420 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !421, file: !316, line: 1094)
!421 = !DISubprogram(name: "erfcf", scope: !313, file: !313, line: 229, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!422 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !423, file: !316, line: 1095)
!423 = !DISubprogram(name: "erfcl", scope: !313, file: !313, line: 229, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!424 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !425, file: !316, line: 1097)
!425 = !DISubprogram(name: "exp2", scope: !313, file: !313, line: 130, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!426 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !427, file: !316, line: 1098)
!427 = !DISubprogram(name: "exp2f", scope: !313, file: !313, line: 130, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!428 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !429, file: !316, line: 1099)
!429 = !DISubprogram(name: "exp2l", scope: !313, file: !313, line: 130, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!430 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !431, file: !316, line: 1101)
!431 = !DISubprogram(name: "expm1", scope: !313, file: !313, line: 119, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!432 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !433, file: !316, line: 1102)
!433 = !DISubprogram(name: "expm1f", scope: !313, file: !313, line: 119, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!434 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !435, file: !316, line: 1103)
!435 = !DISubprogram(name: "expm1l", scope: !313, file: !313, line: 119, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!436 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !437, file: !316, line: 1105)
!437 = !DISubprogram(name: "fdim", scope: !313, file: !313, line: 326, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!438 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !439, file: !316, line: 1106)
!439 = !DISubprogram(name: "fdimf", scope: !313, file: !313, line: 326, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!440 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !441, file: !316, line: 1107)
!441 = !DISubprogram(name: "fdiml", scope: !313, file: !313, line: 326, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!442 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !443, file: !316, line: 1109)
!443 = !DISubprogram(name: "fma", scope: !313, file: !313, line: 335, type: !444, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!444 = !DISubroutineType(types: !445)
!445 = !{!100, !100, !100, !100}
!446 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !447, file: !316, line: 1110)
!447 = !DISubprogram(name: "fmaf", scope: !313, file: !313, line: 335, type: !448, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!448 = !DISubroutineType(types: !449)
!449 = !{!257, !257, !257, !257}
!450 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !451, file: !316, line: 1111)
!451 = !DISubprogram(name: "fmal", scope: !313, file: !313, line: 335, type: !452, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!452 = !DISubroutineType(types: !453)
!453 = !{!262, !262, !262, !262}
!454 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !455, file: !316, line: 1113)
!455 = !DISubprogram(name: "fmax", scope: !313, file: !313, line: 329, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!456 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !457, file: !316, line: 1114)
!457 = !DISubprogram(name: "fmaxf", scope: !313, file: !313, line: 329, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!458 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !459, file: !316, line: 1115)
!459 = !DISubprogram(name: "fmaxl", scope: !313, file: !313, line: 329, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!460 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !461, file: !316, line: 1117)
!461 = !DISubprogram(name: "fmin", scope: !313, file: !313, line: 332, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!462 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !463, file: !316, line: 1118)
!463 = !DISubprogram(name: "fminf", scope: !313, file: !313, line: 332, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!464 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !465, file: !316, line: 1119)
!465 = !DISubprogram(name: "fminl", scope: !313, file: !313, line: 332, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!466 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !467, file: !316, line: 1121)
!467 = !DISubprogram(name: "hypot", scope: !313, file: !313, line: 147, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!468 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !469, file: !316, line: 1122)
!469 = !DISubprogram(name: "hypotf", scope: !313, file: !313, line: 147, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!470 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !471, file: !316, line: 1123)
!471 = !DISubprogram(name: "hypotl", scope: !313, file: !313, line: 147, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!472 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !473, file: !316, line: 1125)
!473 = !DISubprogram(name: "ilogb", scope: !313, file: !313, line: 280, type: !474, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!474 = !DISubroutineType(types: !475)
!475 = !{!71, !100}
!476 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !477, file: !316, line: 1126)
!477 = !DISubprogram(name: "ilogbf", scope: !313, file: !313, line: 280, type: !478, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!478 = !DISubroutineType(types: !479)
!479 = !{!71, !257}
!480 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !481, file: !316, line: 1127)
!481 = !DISubprogram(name: "ilogbl", scope: !313, file: !313, line: 280, type: !482, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!482 = !DISubroutineType(types: !483)
!483 = !{!71, !262}
!484 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !485, file: !316, line: 1129)
!485 = !DISubprogram(name: "lgamma", scope: !313, file: !313, line: 230, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!486 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !487, file: !316, line: 1130)
!487 = !DISubprogram(name: "lgammaf", scope: !313, file: !313, line: 230, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!488 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !489, file: !316, line: 1131)
!489 = !DISubprogram(name: "lgammal", scope: !313, file: !313, line: 230, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!490 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !491, file: !316, line: 1134)
!491 = !DISubprogram(name: "llrint", scope: !313, file: !313, line: 316, type: !492, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!492 = !DISubroutineType(types: !493)
!493 = !{!228, !100}
!494 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !495, file: !316, line: 1135)
!495 = !DISubprogram(name: "llrintf", scope: !313, file: !313, line: 316, type: !496, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!496 = !DISubroutineType(types: !497)
!497 = !{!228, !257}
!498 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !499, file: !316, line: 1136)
!499 = !DISubprogram(name: "llrintl", scope: !313, file: !313, line: 316, type: !500, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!500 = !DISubroutineType(types: !501)
!501 = !{!228, !262}
!502 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !503, file: !316, line: 1138)
!503 = !DISubprogram(name: "llround", scope: !313, file: !313, line: 322, type: !492, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!504 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !505, file: !316, line: 1139)
!505 = !DISubprogram(name: "llroundf", scope: !313, file: !313, line: 322, type: !496, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!506 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !507, file: !316, line: 1140)
!507 = !DISubprogram(name: "llroundl", scope: !313, file: !313, line: 322, type: !500, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!508 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !509, file: !316, line: 1143)
!509 = !DISubprogram(name: "log1p", scope: !313, file: !313, line: 122, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!510 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !511, file: !316, line: 1144)
!511 = !DISubprogram(name: "log1pf", scope: !313, file: !313, line: 122, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!512 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !513, file: !316, line: 1145)
!513 = !DISubprogram(name: "log1pl", scope: !313, file: !313, line: 122, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!514 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !515, file: !316, line: 1147)
!515 = !DISubprogram(name: "log2", scope: !313, file: !313, line: 133, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!516 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !517, file: !316, line: 1148)
!517 = !DISubprogram(name: "log2f", scope: !313, file: !313, line: 133, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!518 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !519, file: !316, line: 1149)
!519 = !DISubprogram(name: "log2l", scope: !313, file: !313, line: 133, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!520 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !521, file: !316, line: 1151)
!521 = !DISubprogram(name: "logb", scope: !313, file: !313, line: 125, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!522 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !523, file: !316, line: 1152)
!523 = !DISubprogram(name: "logbf", scope: !313, file: !313, line: 125, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!524 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !525, file: !316, line: 1153)
!525 = !DISubprogram(name: "logbl", scope: !313, file: !313, line: 125, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!526 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !527, file: !316, line: 1155)
!527 = !DISubprogram(name: "lrint", scope: !313, file: !313, line: 314, type: !528, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!528 = !DISubroutineType(types: !529)
!529 = !{!82, !100}
!530 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !531, file: !316, line: 1156)
!531 = !DISubprogram(name: "lrintf", scope: !313, file: !313, line: 314, type: !532, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!532 = !DISubroutineType(types: !533)
!533 = !{!82, !257}
!534 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !535, file: !316, line: 1157)
!535 = !DISubprogram(name: "lrintl", scope: !313, file: !313, line: 314, type: !536, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!536 = !DISubroutineType(types: !537)
!537 = !{!82, !262}
!538 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !539, file: !316, line: 1159)
!539 = !DISubprogram(name: "lround", scope: !313, file: !313, line: 320, type: !528, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!540 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !541, file: !316, line: 1160)
!541 = !DISubprogram(name: "lroundf", scope: !313, file: !313, line: 320, type: !532, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!542 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !543, file: !316, line: 1161)
!543 = !DISubprogram(name: "lroundl", scope: !313, file: !313, line: 320, type: !536, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!544 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !545, file: !316, line: 1163)
!545 = !DISubprogram(name: "nan", scope: !313, file: !313, line: 201, type: !98, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!546 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !547, file: !316, line: 1164)
!547 = !DISubprogram(name: "nanf", scope: !313, file: !313, line: 201, type: !548, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!548 = !DISubroutineType(types: !549)
!549 = !{!257, !101}
!550 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !551, file: !316, line: 1165)
!551 = !DISubprogram(name: "nanl", scope: !313, file: !313, line: 201, type: !552, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!552 = !DISubroutineType(types: !553)
!553 = !{!262, !101}
!554 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !555, file: !316, line: 1167)
!555 = !DISubprogram(name: "nearbyint", scope: !313, file: !313, line: 294, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!556 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !557, file: !316, line: 1168)
!557 = !DISubprogram(name: "nearbyintf", scope: !313, file: !313, line: 294, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!558 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !559, file: !316, line: 1169)
!559 = !DISubprogram(name: "nearbyintl", scope: !313, file: !313, line: 294, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!560 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !561, file: !316, line: 1171)
!561 = !DISubprogram(name: "nextafter", scope: !313, file: !313, line: 259, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!562 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !563, file: !316, line: 1172)
!563 = !DISubprogram(name: "nextafterf", scope: !313, file: !313, line: 259, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!564 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !565, file: !316, line: 1173)
!565 = !DISubprogram(name: "nextafterl", scope: !313, file: !313, line: 259, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!566 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !567, file: !316, line: 1175)
!567 = !DISubprogram(name: "nexttoward", scope: !313, file: !313, line: 261, type: !568, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!568 = !DISubroutineType(types: !569)
!569 = !{!100, !100, !262}
!570 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !571, file: !316, line: 1176)
!571 = !DISubprogram(name: "nexttowardf", scope: !313, file: !313, line: 261, type: !572, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!572 = !DISubroutineType(types: !573)
!573 = !{!257, !257, !262}
!574 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !575, file: !316, line: 1177)
!575 = !DISubprogram(name: "nexttowardl", scope: !313, file: !313, line: 261, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!576 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !577, file: !316, line: 1179)
!577 = !DISubprogram(name: "remainder", scope: !313, file: !313, line: 272, type: !323, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!578 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !579, file: !316, line: 1180)
!579 = !DISubprogram(name: "remainderf", scope: !313, file: !313, line: 272, type: !406, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!580 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !581, file: !316, line: 1181)
!581 = !DISubprogram(name: "remainderl", scope: !313, file: !313, line: 272, type: !410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!582 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !583, file: !316, line: 1183)
!583 = !DISubprogram(name: "remquo", scope: !313, file: !313, line: 307, type: !584, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!584 = !DISubroutineType(types: !585)
!585 = !{!100, !100, !100, !343}
!586 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !587, file: !316, line: 1184)
!587 = !DISubprogram(name: "remquof", scope: !313, file: !313, line: 307, type: !588, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!588 = !DISubroutineType(types: !589)
!589 = !{!257, !257, !257, !343}
!590 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !591, file: !316, line: 1185)
!591 = !DISubprogram(name: "remquol", scope: !313, file: !313, line: 307, type: !592, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!592 = !DISubroutineType(types: !593)
!593 = !{!262, !262, !262, !343}
!594 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !595, file: !316, line: 1187)
!595 = !DISubprogram(name: "rint", scope: !313, file: !313, line: 256, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!596 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !597, file: !316, line: 1188)
!597 = !DISubprogram(name: "rintf", scope: !313, file: !313, line: 256, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!598 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !599, file: !316, line: 1189)
!599 = !DISubprogram(name: "rintl", scope: !313, file: !313, line: 256, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!600 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !601, file: !316, line: 1191)
!601 = !DISubprogram(name: "round", scope: !313, file: !313, line: 298, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!602 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !603, file: !316, line: 1192)
!603 = !DISubprogram(name: "roundf", scope: !313, file: !313, line: 298, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!604 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !605, file: !316, line: 1193)
!605 = !DISubprogram(name: "roundl", scope: !313, file: !313, line: 298, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!606 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !607, file: !316, line: 1195)
!607 = !DISubprogram(name: "scalbln", scope: !313, file: !313, line: 290, type: !608, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!608 = !DISubroutineType(types: !609)
!609 = !{!100, !100, !82}
!610 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !611, file: !316, line: 1196)
!611 = !DISubprogram(name: "scalblnf", scope: !313, file: !313, line: 290, type: !612, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!612 = !DISubroutineType(types: !613)
!613 = !{!257, !257, !82}
!614 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !615, file: !316, line: 1197)
!615 = !DISubprogram(name: "scalblnl", scope: !313, file: !313, line: 290, type: !616, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!616 = !DISubroutineType(types: !617)
!617 = !{!262, !262, !82}
!618 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !619, file: !316, line: 1199)
!619 = !DISubprogram(name: "scalbn", scope: !313, file: !313, line: 276, type: !346, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!620 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !621, file: !316, line: 1200)
!621 = !DISubprogram(name: "scalbnf", scope: !313, file: !313, line: 276, type: !622, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!622 = !DISubroutineType(types: !623)
!623 = !{!257, !257, !71}
!624 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !625, file: !316, line: 1201)
!625 = !DISubprogram(name: "scalbnl", scope: !313, file: !313, line: 276, type: !626, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!626 = !DISubroutineType(types: !627)
!627 = !{!262, !262, !71}
!628 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !629, file: !316, line: 1203)
!629 = !DISubprogram(name: "tgamma", scope: !313, file: !313, line: 235, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!630 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !631, file: !316, line: 1204)
!631 = !DISubprogram(name: "tgammaf", scope: !313, file: !313, line: 235, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!632 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !633, file: !316, line: 1205)
!633 = !DISubprogram(name: "tgammal", scope: !313, file: !313, line: 235, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!634 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !635, file: !316, line: 1207)
!635 = !DISubprogram(name: "trunc", scope: !313, file: !313, line: 302, type: !314, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!636 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !637, file: !316, line: 1208)
!637 = !DISubprogram(name: "truncf", scope: !313, file: !313, line: 302, type: !378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!638 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !5, entity: !639, file: !316, line: 1209)
!639 = !DISubprogram(name: "truncl", scope: !313, file: !313, line: 302, type: !382, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!640 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !283, file: !641, line: 38)
!641 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/math.h", directory: "")
!642 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !643, file: !641, line: 54)
!643 = !DISubprogram(name: "modf", linkageName: "_ZSt4modfePe", scope: !5, file: !316, line: 380, type: !644, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!644 = !DISubroutineType(types: !645)
!645 = !{!262, !262, !646}
!646 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !262, size: 64)
!647 = !{i32 7, !"Dwarf Version", i32 4}
!648 = !{i32 2, !"Debug Info Version", i32 3}
!649 = !{i32 1, !"wchar_size", i32 4}
!650 = !{i32 7, !"PIC Level", i32 2}
!651 = !{i32 7, !"PIE Level", i32 2}
!652 = !{!"clang version 10.0.0 "}
!653 = distinct !DISubprogram(name: "DevirtualizeInfo", linkageName: "_ZN16DevirtualizeInfoC2Ev", scope: !654, file: !1, line: 23, type: !661, scopeLine: 24, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !660, retainedNodes: !678)
!654 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "DevirtualizeInfo", file: !655, line: 6, size: 896, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !656, vtableHolder: !658)
!655 = !DIFile(filename: "../elements/standard/devirtualizeinfo.hh", directory: "/home/john/projects/click/ir-dir")
!656 = !{!657, !660, !664, !669}
!657 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !654, baseType: !658, flags: DIFlagPublic, extraData: i32 0)
!658 = !DICompositeType(tag: DW_TAG_class_type, name: "Element", file: !659, line: 29, flags: DIFlagFwdDecl, identifier: "_ZTS7Element")
!659 = !DIFile(filename: "../dummy_inc/click/element.hh", directory: "/home/john/projects/click/ir-dir")
!660 = !DISubprogram(name: "DevirtualizeInfo", scope: !654, file: !655, line: 10, type: !661, scopeLine: 10, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!661 = !DISubroutineType(types: !662)
!662 = !{null, !663}
!663 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !654, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!664 = !DISubprogram(name: "class_name", linkageName: "_ZNK16DevirtualizeInfo10class_nameEv", scope: !654, file: !655, line: 12, type: !665, scopeLine: 12, containingType: !654, virtualIndex: 9, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!665 = !DISubroutineType(types: !666)
!666 = !{!101, !667}
!667 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !668, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!668 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !654)
!669 = !DISubprogram(name: "configure", linkageName: "_ZN16DevirtualizeInfo9configureER6VectorI6StringEP12ErrorHandler", scope: !654, file: !655, line: 13, type: !670, scopeLine: 13, containingType: !654, virtualIndex: 17, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!670 = !DISubroutineType(types: !671)
!671 = !{!71, !663, !672, !675}
!672 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !673, size: 64)
!673 = !DICompositeType(tag: DW_TAG_class_type, name: "Vector<String>", file: !674, line: 13, flags: DIFlagFwdDecl, identifier: "_ZTS6VectorI6StringE")
!674 = !DIFile(filename: "../dummy_inc/click/ipaddress.hh", directory: "/home/john/projects/click/ir-dir")
!675 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !676, size: 64)
!676 = !DICompositeType(tag: DW_TAG_class_type, name: "ErrorHandler", file: !677, line: 6, flags: DIFlagFwdDecl, identifier: "_ZTS12ErrorHandler")
!677 = !DIFile(filename: "../dummy_inc/click/handler.hh", directory: "/home/john/projects/click/ir-dir")
!678 = !{!679}
!679 = !DILocalVariable(name: "this", arg: 1, scope: !653, type: !680, flags: DIFlagArtificial | DIFlagObjectPointer)
!680 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !654, size: 64)
!681 = !DILocation(line: 0, scope: !653)
!682 = !DILocation(line: 24, column: 1, scope: !653)
!683 = !DILocation(line: 23, column: 19, scope: !653)
!684 = !{!685, !685, i64 0}
!685 = !{!"vtable pointer", !686, i64 0}
!686 = !{!"Simple C++ TBAA"}
!687 = !DILocation(line: 25, column: 1, scope: !653)
!688 = distinct !DISubprogram(name: "configure", linkageName: "_ZN16DevirtualizeInfo9configureER6VectorI6StringEP12ErrorHandler", scope: !654, file: !1, line: 28, type: !670, scopeLine: 29, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !669, retainedNodes: !689)
!689 = !{!690, !691, !692}
!690 = !DILocalVariable(name: "this", arg: 1, scope: !688, type: !680, flags: DIFlagArtificial | DIFlagObjectPointer)
!691 = !DILocalVariable(arg: 2, scope: !688, file: !1, line: 28, type: !672)
!692 = !DILocalVariable(arg: 3, scope: !688, file: !1, line: 28, type: !675)
!693 = !DILocation(line: 0, scope: !688)
!694 = !DILocation(line: 30, column: 3, scope: !688)
!695 = distinct !DISubprogram(name: "~DevirtualizeInfo", linkageName: "_ZN16DevirtualizeInfoD0Ev", scope: !654, file: !655, line: 6, type: !661, scopeLine: 6, flags: DIFlagArtificial | DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !696, retainedNodes: !697)
!696 = !DISubprogram(name: "~DevirtualizeInfo", scope: !654, type: !661, containingType: !654, virtualIndex: 0, flags: DIFlagPublic | DIFlagArtificial | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!697 = !{!698}
!698 = !DILocalVariable(name: "this", arg: 1, scope: !695, type: !680, flags: DIFlagArtificial | DIFlagObjectPointer)
!699 = !DILocation(line: 0, scope: !695)
!700 = !DILocation(line: 6, column: 7, scope: !695)
!701 = distinct !DISubprogram(name: "class_name", linkageName: "_ZNK16DevirtualizeInfo10class_nameEv", scope: !654, file: !655, line: 12, type: !665, scopeLine: 12, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !664, retainedNodes: !702)
!702 = !{!703}
!703 = !DILocalVariable(name: "this", arg: 1, scope: !701, type: !704, flags: DIFlagArtificial | DIFlagObjectPointer)
!704 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !668, size: 64)
!705 = !DILocation(line: 0, scope: !701)
!706 = !DILocation(line: 12, column: 36, scope: !701)