; ModuleID = '../elements/standard/resize.cc'
source_filename = "../elements/standard/resize.cc"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%class.Resize = type { %class.Element.base, i32, i32, [4 x i8] }
%class.Element.base = type <{ i32 (...)**, [2 x %"class.Element::Port"*], [4 x %"class.Element::Port"], [2 x i32], %class.Router*, i32 }>
%"class.Element::Port" = type <{ %class.Element*, i32, [4 x i8] }>
%class.Element = type <{ i32 (...)**, [2 x %"class.Element::Port"*], [4 x %"class.Element::Port"], [2 x i32], %class.Router*, i32, [4 x i8] }>
%class.Router = type opaque
%class.Vector = type { %class.vector_memory }
%class.vector_memory = type { %class.String*, i32, i32 }
%class.String = type { %"struct.String::rep_t" }
%"struct.String::rep_t" = type { i8*, i32, %"struct.String::memo_t"* }
%"struct.String::memo_t" = type { i32, i32, i32, [8 x i8] }
%class.ErrorHandler = type <{ i32 (...)**, i32, [4 x i8] }>
%class.Args = type { %class.ArgContext.base, i8, i8, i8, %class.Vector*, %class.Vector.0, %"struct.Args::Slot"*, [48 x i8] }
%class.ArgContext.base = type <{ %class.Element*, %class.ErrorHandler*, i8*, i8 }>
%class.Vector.0 = type { %class.vector_memory.1 }
%class.vector_memory.1 = type { %struct.char_array*, i32, i32 }
%struct.char_array = type opaque
%"struct.Args::Slot" = type { i32 (...)**, %"struct.Args::Slot"* }
%class.Packet = type { %class.atomic_uint32_t, %class.Packet*, i8*, i8*, i8*, i8*, %"struct.Packet::AllAnno", void (i8*, i64, i8*)*, i8* }
%class.atomic_uint32_t = type { i32 }
%"struct.Packet::AllAnno" = type { %"union.Packet::Anno", i8*, i8*, i8*, i32, [8 x i8], %class.Packet*, %class.Packet* }
%"union.Packet::Anno" = type { [6 x i64] }
%class.WritablePacket = type { %class.Packet }
%class.Task = type opaque
%class.Timer = type opaque
%class.IntArg = type { i32, i32 }
%class.ArgContext = type <{ %class.Element*, %class.ErrorHandler*, i8*, i8, [7 x i8] }>

$_ZN6ResizeD0Ev = comdat any

$_ZNK6Resize10class_nameEv = comdat any

$_ZNK6Resize10port_countEv = comdat any

$_ZNK6Resize5flagsEv = comdat any

$_ZNK6Resize20can_live_reconfigureEv = comdat any

$_Z14args_base_readIiEvP4ArgsPKciRT_ = comdat any

$_ZN4Args9base_readIiEEvPKciRT_ = comdat any

$_ZNK6String6lengthEv = comdat any

$__clang_call_terminate = comdat any

@_ZTV6Resize = dso_local unnamed_addr constant { [29 x i8*] } { [29 x i8*] [i8* null, i8* bitcast ({ i8*, i8*, i8* }* @_ZTI6Resize to i8*), i8* bitcast (void (%class.Element*)* @_ZN7ElementD2Ev to i8*), i8* bitcast (void (%class.Resize*)* @_ZN6ResizeD0Ev to i8*), i8* bitcast (void (%class.Element*, i32, %class.Packet*)* @_ZN7Element4pushEiP6Packet to i8*), i8* bitcast (%class.Packet* (%class.Element*, i32)* @_ZN7Element4pullEi to i8*), i8* bitcast (%class.Packet* (%class.Resize*, %class.Packet*)* @_ZN6Resize13simple_actionEP6Packet to i8*), i8* bitcast (i1 (%class.Element*, %class.Task*)* @_ZN7Element8run_taskEP4Task to i8*), i8* bitcast (void (%class.Element*, %class.Timer*)* @_ZN7Element9run_timerEP5Timer to i8*), i8* bitcast (void (%class.Element*, i32, i32)* @_ZN7Element8selectedEii to i8*), i8* bitcast (void (%class.Element*, i32)* @_ZN7Element8selectedEi to i8*), i8* bitcast (i8* (%class.Resize*)* @_ZNK6Resize10class_nameEv to i8*), i8* bitcast (i8* (%class.Resize*)* @_ZNK6Resize10port_countEv to i8*), i8* bitcast (i8* (%class.Element*)* @_ZNK7Element10processingEv to i8*), i8* bitcast (i8* (%class.Element*)* @_ZNK7Element9flow_codeEv to i8*), i8* bitcast (i8* (%class.Resize*)* @_ZNK6Resize5flagsEv to i8*), i8* bitcast (i8* (%class.Element*, i8*)* @_ZN7Element4castEPKc to i8*), i8* bitcast (i8* (%class.Element*, i1, i32, i8*)* @_ZN7Element9port_castEbiPKc to i8*), i8* bitcast (i32 (%class.Element*)* @_ZNK7Element15configure_phaseEv to i8*), i8* bitcast (i32 (%class.Resize*, %class.Vector*, %class.ErrorHandler*)* @_ZN6Resize9configureER6VectorI6StringEP12ErrorHandler to i8*), i8* bitcast (void (%class.Resize*)* @_ZN6Resize12add_handlersEv to i8*), i8* bitcast (i32 (%class.Element*, %class.ErrorHandler*)* @_ZN7Element10initializeEP12ErrorHandler to i8*), i8* bitcast (void (%class.Element*, %class.Element*, %class.ErrorHandler*)* @_ZN7Element10take_stateEPS_P12ErrorHandler to i8*), i8* bitcast (%class.Element* (%class.Element*)* @_ZNK7Element15hotswap_elementEv to i8*), i8* bitcast (void (%class.Element*, i32)* @_ZN7Element7cleanupENS_12CleanupStageE to i8*), i8* bitcast (void (%class.String*, %class.Element*)* @_ZNK7Element11declarationEv to i8*), i8* bitcast (i1 (%class.Resize*)* @_ZNK6Resize20can_live_reconfigureEv to i8*), i8* bitcast (i32 (%class.Element*, %class.Vector*, %class.ErrorHandler*)* @_ZN7Element16live_reconfigureER6VectorI6StringEP12ErrorHandler to i8*), i8* bitcast (i32 (%class.Element*, i32, i8*)* @_ZN7Element5llrpcEjPv to i8*)] }, align 8
@.str = private unnamed_addr constant [5 x i8] c"HEAD\00", align 1
@.str.1 = private unnamed_addr constant [5 x i8] c"TAIL\00", align 1
@.str.2 = private unnamed_addr constant [5 x i8] c"head\00", align 1
@.str.3 = private unnamed_addr constant [5 x i8] c"tail\00", align 1
@_ZTVN10__cxxabiv120__si_class_type_infoE = external global i8*
@_ZTS6Resize = dso_local constant [8 x i8] c"6Resize\00", align 1
@_ZTI7Element = external constant i8*
@_ZTI6Resize = dso_local constant { i8*, i8*, i8* } { i8* bitcast (i8** getelementptr inbounds (i8*, i8** @_ZTVN10__cxxabiv120__si_class_type_infoE, i64 2) to i8*), i8* getelementptr inbounds ([8 x i8], [8 x i8]* @_ZTS6Resize, i32 0, i32 0), i8* bitcast (i8** @_ZTI7Element to i8*) }, align 8
@.str.4 = private unnamed_addr constant [7 x i8] c"Resize\00", align 1
@_ZN7Element9PORTS_1_1E = external constant [0 x i8], align 1
@.str.5 = private unnamed_addr constant [3 x i8] c"S0\00", align 1
@.str.6 = private unnamed_addr constant [15 x i8] c"invalid number\00", align 1
@.str.7 = private unnamed_addr constant [18 x i8] c"_r.memo->refcount\00", align 1
@.str.8 = private unnamed_addr constant [29 x i8] c"../dummy_inc/click/string.hh\00", align 1
@__PRETTY_FUNCTION__._ZNK6String5derefEv = private unnamed_addr constant [27 x i8] c"void String::deref() const\00", align 1

@_ZN6ResizeC1Ev = dso_local unnamed_addr alias void (%class.Resize*), void (%class.Resize*)* @_ZN6ResizeC2Ev

; Function Attrs: sspstrong uwtable
define dso_local void @_ZN6ResizeC2Ev(%class.Resize* %0) unnamed_addr #0 align 2 !dbg !2495 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2524, metadata !DIExpression()), !dbg !2526
  %2 = bitcast %class.Resize* %0 to %class.Element*, !dbg !2527
  tail call void @_ZN7ElementC2Ev(%class.Element* %2), !dbg !2528
  %3 = getelementptr %class.Resize, %class.Resize* %0, i64 0, i32 0, i32 0, !dbg !2527
  store i32 (...)** bitcast (i8** getelementptr inbounds ({ [29 x i8*] }, { [29 x i8*] }* @_ZTV6Resize, i64 0, inrange i32 0, i64 2) to i32 (...)**), i32 (...)*** %3, align 8, !dbg !2527, !tbaa !2529
  ret void, !dbg !2532
}

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare void @_ZN7ElementC2Ev(%class.Element*) unnamed_addr #2

; Function Attrs: sspstrong uwtable
define dso_local i32 @_ZN6Resize9configureER6VectorI6StringEP12ErrorHandler(%class.Resize* %0, %class.Vector* dereferenceable(16) %1, %class.ErrorHandler* %2) unnamed_addr #0 align 2 personality i8* bitcast (i32 (...)* @__gxx_personality_v0 to i8*) !dbg !2533 {
  %4 = alloca %class.Args, align 8
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2535, metadata !DIExpression()), !dbg !2538
  call void @llvm.dbg.value(metadata %class.Vector* %1, metadata !2536, metadata !DIExpression()), !dbg !2538
  call void @llvm.dbg.value(metadata %class.ErrorHandler* %2, metadata !2537, metadata !DIExpression()), !dbg !2538
  %5 = getelementptr inbounds %class.Resize, %class.Resize* %0, i64 0, i32 1, !dbg !2539
  store i32 0, i32* %5, align 4, !dbg !2540, !tbaa !2541
  %6 = getelementptr inbounds %class.Resize, %class.Resize* %0, i64 0, i32 2, !dbg !2545
  store i32 0, i32* %6, align 8, !dbg !2546, !tbaa !2547
  %7 = bitcast %class.Args* %4 to i8*, !dbg !2548
  call void @llvm.lifetime.start.p0i8(i64 112, i8* nonnull %7) #11, !dbg !2548
  %8 = bitcast %class.Resize* %0 to %class.Element*, !dbg !2549
  call void @_ZN4ArgsC1ERK6VectorI6StringEPK7ElementP12ErrorHandler(%class.Args* nonnull %4, %class.Vector* nonnull dereferenceable(16) %1, %class.Element* %8, %class.ErrorHandler* %2), !dbg !2548
  call void @llvm.dbg.value(metadata %class.Args* %4, metadata !2550, metadata !DIExpression()), !dbg !2558
  call void @llvm.dbg.value(metadata i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str, i64 0, i64 0), metadata !2556, metadata !DIExpression()), !dbg !2558
  call void @llvm.dbg.value(metadata i32* %5, metadata !2557, metadata !DIExpression()), !dbg !2558
  call void @llvm.dbg.value(metadata %class.Args* %4, metadata !2560, metadata !DIExpression()), !dbg !2569
  call void @llvm.dbg.value(metadata i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str, i64 0, i64 0), metadata !2566, metadata !DIExpression()), !dbg !2569
  call void @llvm.dbg.value(metadata i32 2, metadata !2567, metadata !DIExpression()), !dbg !2569
  call void @llvm.dbg.value(metadata i32* %5, metadata !2568, metadata !DIExpression()), !dbg !2569
  invoke void @_Z14args_base_readIiEvP4ArgsPKciRT_(%class.Args* nonnull %4, i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str, i64 0, i64 0), i32 2, i32* nonnull dereferenceable(4) %5)
          to label %9 unwind label %13, !dbg !2571

9:                                                ; preds = %3
  call void @llvm.dbg.value(metadata %class.Args* %4, metadata !2550, metadata !DIExpression()), !dbg !2572
  call void @llvm.dbg.value(metadata i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.1, i64 0, i64 0), metadata !2556, metadata !DIExpression()), !dbg !2572
  call void @llvm.dbg.value(metadata i32* %6, metadata !2557, metadata !DIExpression()), !dbg !2572
  call void @llvm.dbg.value(metadata %class.Args* %4, metadata !2560, metadata !DIExpression()), !dbg !2574
  call void @llvm.dbg.value(metadata i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.1, i64 0, i64 0), metadata !2566, metadata !DIExpression()), !dbg !2574
  call void @llvm.dbg.value(metadata i32 2, metadata !2567, metadata !DIExpression()), !dbg !2574
  call void @llvm.dbg.value(metadata i32* %6, metadata !2568, metadata !DIExpression()), !dbg !2574
  invoke void @_Z14args_base_readIiEvP4ArgsPKciRT_(%class.Args* nonnull %4, i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.1, i64 0, i64 0), i32 2, i32* nonnull dereferenceable(4) %6)
          to label %10 unwind label %13, !dbg !2576

10:                                               ; preds = %9
  %11 = invoke i32 @_ZN4Args8completeEv(%class.Args* nonnull %4)
          to label %12 unwind label %13, !dbg !2577

12:                                               ; preds = %10
  call void @_ZN4ArgsD1Ev(%class.Args* nonnull %4) #11, !dbg !2578
  call void @llvm.lifetime.end.p0i8(i64 112, i8* nonnull %7) #11, !dbg !2578
  ret i32 %11, !dbg !2578

13:                                               ; preds = %9, %3, %10
  %14 = landingpad { i8*, i32 }
          cleanup, !dbg !2579
  call void @_ZN4ArgsD1Ev(%class.Args* nonnull %4) #11, !dbg !2578
  call void @llvm.lifetime.end.p0i8(i64 112, i8* nonnull %7) #11, !dbg !2578
  resume { i8*, i32 } %14, !dbg !2578
}

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #3

declare void @_ZN4ArgsC1ERK6VectorI6StringEPK7ElementP12ErrorHandler(%class.Args*, %class.Vector* dereferenceable(16), %class.Element*, %class.ErrorHandler*) unnamed_addr #2

declare i32 @__gxx_personality_v0(...)

declare i32 @_ZN4Args8completeEv(%class.Args*) local_unnamed_addr #2

; Function Attrs: nounwind
declare void @_ZN4ArgsD1Ev(%class.Args*) unnamed_addr #4

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #3

; Function Attrs: sspstrong uwtable
define dso_local %class.Packet* @_ZN6Resize13simple_actionEP6Packet(%class.Resize* nocapture readonly %0, %class.Packet* %1) unnamed_addr #0 align 2 !dbg !2580 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2582, metadata !DIExpression()), !dbg !2584
  call void @llvm.dbg.value(metadata %class.Packet* %1, metadata !2583, metadata !DIExpression()), !dbg !2584
  %3 = getelementptr inbounds %class.Resize, %class.Resize* %0, i64 0, i32 1, !dbg !2585
  %4 = load i32, i32* %3, align 4, !dbg !2585, !tbaa !2541
  %5 = icmp sgt i32 %4, 0, !dbg !2587
  br i1 %5, label %6, label %28, !dbg !2588

6:                                                ; preds = %2
  call void @llvm.dbg.value(metadata %class.Packet* %1, metadata !2589, metadata !DIExpression()), !dbg !2593
  call void @llvm.dbg.value(metadata i32 %4, metadata !2592, metadata !DIExpression()), !dbg !2593
  call void @llvm.dbg.value(metadata %class.Packet* %1, metadata !2596, metadata !DIExpression()), !dbg !2599
  %7 = tail call i8* @_ZNK6Packet4dataEv(%class.Packet* %1), !dbg !2602
  call void @llvm.dbg.value(metadata %class.Packet* %1, metadata !2603, metadata !DIExpression()), !dbg !2606
  %8 = getelementptr inbounds %class.Packet, %class.Packet* %1, i64 0, i32 2, !dbg !2608
  %9 = bitcast i8** %8 to i64*, !dbg !2608
  %10 = load i64, i64* %9, align 8, !dbg !2608, !tbaa !2609
  %11 = ptrtoint i8* %7 to i64, !dbg !2615
  %12 = sub i64 %11, %10, !dbg !2615
  %13 = trunc i64 %12 to i32, !dbg !2602
  %14 = icmp ugt i32 %4, %13, !dbg !2616
  br i1 %14, label %21, label %15, !dbg !2617

15:                                               ; preds = %6
  %16 = getelementptr inbounds %class.Packet, %class.Packet* %1, i64 0, i32 3, !dbg !2618
  %17 = load i8*, i8** %16, align 8, !dbg !2620, !tbaa !2621
  %18 = zext i32 %4 to i64, !dbg !2620
  %19 = sub nsw i64 0, %18, !dbg !2620
  %20 = getelementptr inbounds i8, i8* %17, i64 %19, !dbg !2620
  store i8* %20, i8** %16, align 8, !dbg !2620, !tbaa !2621
  call void @llvm.dbg.value(metadata %class.Packet* %23, metadata !2583, metadata !DIExpression()), !dbg !2584
  br label %25, !dbg !2622

21:                                               ; preds = %6
  %22 = tail call %class.WritablePacket* @_ZN6Packet14expensive_pushEj(%class.Packet* nonnull %1, i32 %4), !dbg !2623
  %23 = getelementptr %class.WritablePacket, %class.WritablePacket* %22, i64 0, i32 0, !dbg !2623
  call void @llvm.dbg.value(metadata %class.Packet* %23, metadata !2583, metadata !DIExpression()), !dbg !2584
  %24 = icmp eq %class.WritablePacket* %22, null, !dbg !2624
  br i1 %24, label %71, label %25, !dbg !2622

25:                                               ; preds = %21, %15
  %26 = phi %class.Packet* [ %1, %15 ], [ %23, %21 ]
  %27 = load i32, i32* %3, align 4, !dbg !2626, !tbaa !2541
  br label %28, !dbg !2626

28:                                               ; preds = %25, %2
  %29 = phi i32 [ %27, %25 ], [ %4, %2 ], !dbg !2626
  %30 = phi %class.Packet* [ %26, %25 ], [ %1, %2 ]
  call void @llvm.dbg.value(metadata %class.Packet* %30, metadata !2583, metadata !DIExpression()), !dbg !2584
  %31 = icmp slt i32 %29, 0, !dbg !2628
  br i1 %31, label %32, label %37, !dbg !2629

32:                                               ; preds = %28
  %33 = sub nsw i32 0, %29, !dbg !2630
  %34 = tail call i32 @_ZNK6Packet6lengthEv(%class.Packet* %30), !dbg !2632
  call void @llvm.dbg.value(metadata i32 %33, metadata !2633, metadata !DIExpression()), !dbg !2639
  call void @llvm.dbg.value(metadata i32 %34, metadata !2638, metadata !DIExpression()), !dbg !2639
  %35 = icmp ult i32 %34, %33, !dbg !2641
  %36 = select i1 %35, i32 %34, i32 %33, !dbg !2639
  tail call void @_ZN6Packet4pullEj(%class.Packet* %30, i32 %36), !dbg !2643
  br label %37, !dbg !2644

37:                                               ; preds = %32, %28
  %38 = getelementptr inbounds %class.Resize, %class.Resize* %0, i64 0, i32 2, !dbg !2645
  %39 = load i32, i32* %38, align 8, !dbg !2645, !tbaa !2547
  %40 = icmp sgt i32 %39, 0, !dbg !2647
  br i1 %40, label %41, label %62, !dbg !2648

41:                                               ; preds = %37
  call void @llvm.dbg.value(metadata %class.Packet* %30, metadata !2649, metadata !DIExpression()), !dbg !2653
  call void @llvm.dbg.value(metadata i32 %39, metadata !2652, metadata !DIExpression()), !dbg !2653
  call void @llvm.dbg.value(metadata %class.Packet* %30, metadata !2656, metadata !DIExpression()), !dbg !2659
  call void @llvm.dbg.value(metadata %class.Packet* %30, metadata !2662, metadata !DIExpression()), !dbg !2665
  %42 = getelementptr inbounds %class.Packet, %class.Packet* %30, i64 0, i32 5, !dbg !2667
  %43 = bitcast i8** %42 to i64*, !dbg !2667
  %44 = load i64, i64* %43, align 8, !dbg !2667, !tbaa !2668
  %45 = tail call i8* @_ZNK6Packet8end_dataEv(%class.Packet* %30), !dbg !2669
  %46 = ptrtoint i8* %45 to i64, !dbg !2670
  %47 = sub i64 %44, %46, !dbg !2670
  %48 = trunc i64 %47 to i32, !dbg !2671
  %49 = icmp ugt i32 %39, %48, !dbg !2672
  br i1 %49, label %55, label %50, !dbg !2673

50:                                               ; preds = %41
  %51 = getelementptr inbounds %class.Packet, %class.Packet* %30, i64 0, i32 4, !dbg !2674
  %52 = load i8*, i8** %51, align 8, !dbg !2676, !tbaa !2677
  %53 = zext i32 %39 to i64, !dbg !2676
  %54 = getelementptr inbounds i8, i8* %52, i64 %53, !dbg !2676
  store i8* %54, i8** %51, align 8, !dbg !2676, !tbaa !2677
  call void @llvm.dbg.value(metadata %class.Packet* %57, metadata !2583, metadata !DIExpression()), !dbg !2584
  br label %59, !dbg !2678

55:                                               ; preds = %41
  %56 = tail call %class.WritablePacket* @_ZN6Packet13expensive_putEj(%class.Packet* nonnull %30, i32 %39), !dbg !2679
  %57 = getelementptr %class.WritablePacket, %class.WritablePacket* %56, i64 0, i32 0, !dbg !2679
  call void @llvm.dbg.value(metadata %class.Packet* %57, metadata !2583, metadata !DIExpression()), !dbg !2584
  %58 = icmp eq %class.WritablePacket* %56, null, !dbg !2680
  br i1 %58, label %71, label %59, !dbg !2678

59:                                               ; preds = %55, %50
  %60 = phi %class.Packet* [ %30, %50 ], [ %57, %55 ]
  %61 = load i32, i32* %38, align 8, !dbg !2682, !tbaa !2547
  br label %62, !dbg !2682

62:                                               ; preds = %59, %37
  %63 = phi i32 [ %61, %59 ], [ %39, %37 ], !dbg !2682
  %64 = phi %class.Packet* [ %60, %59 ], [ %30, %37 ], !dbg !2584
  call void @llvm.dbg.value(metadata %class.Packet* %64, metadata !2583, metadata !DIExpression()), !dbg !2584
  %65 = icmp slt i32 %63, 0, !dbg !2684
  br i1 %65, label %66, label %71, !dbg !2685

66:                                               ; preds = %62
  %67 = sub nsw i32 0, %63, !dbg !2686
  %68 = tail call i32 @_ZNK6Packet6lengthEv(%class.Packet* %64), !dbg !2688
  call void @llvm.dbg.value(metadata i32 %67, metadata !2633, metadata !DIExpression()), !dbg !2689
  call void @llvm.dbg.value(metadata i32 %68, metadata !2638, metadata !DIExpression()), !dbg !2689
  %69 = icmp ult i32 %68, %67, !dbg !2691
  %70 = select i1 %69, i32 %68, i32 %67, !dbg !2689
  tail call void @_ZN6Packet4takeEj(%class.Packet* %64, i32 %70), !dbg !2692
  br label %71, !dbg !2693

71:                                               ; preds = %62, %66, %55, %21
  %72 = phi %class.Packet* [ null, %21 ], [ null, %55 ], [ %64, %66 ], [ %64, %62 ], !dbg !2584
  ret %class.Packet* %72, !dbg !2694
}

declare void @_ZN6Packet4pullEj(%class.Packet*, i32) local_unnamed_addr #2

declare i32 @_ZNK6Packet6lengthEv(%class.Packet*) local_unnamed_addr #2

declare void @_ZN6Packet4takeEj(%class.Packet*, i32) local_unnamed_addr #2

; Function Attrs: sspstrong uwtable
define dso_local void @_ZN6Resize12add_handlersEv(%class.Resize* %0) unnamed_addr #0 align 2 !dbg !2695 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2697, metadata !DIExpression()), !dbg !2698
  %2 = bitcast %class.Resize* %0 to %class.Element*, !dbg !2699
  %3 = getelementptr inbounds %class.Resize, %class.Resize* %0, i64 0, i32 1, !dbg !2700
  tail call void @_ZN7Element17add_data_handlersEPKciPi(%class.Element* %2, i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.2, i64 0, i64 0), i32 3, i32* nonnull %3), !dbg !2699
  %4 = getelementptr inbounds %class.Resize, %class.Resize* %0, i64 0, i32 2, !dbg !2701
  tail call void @_ZN7Element17add_data_handlersEPKciPi(%class.Element* %2, i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.3, i64 0, i64 0), i32 3, i32* nonnull %4), !dbg !2702
  ret void, !dbg !2703
}

declare void @_ZN7Element17add_data_handlersEPKciPi(%class.Element*, i8*, i32, i32*) local_unnamed_addr #2

; Function Attrs: nounwind
declare void @_ZN7ElementD2Ev(%class.Element*) unnamed_addr #4

; Function Attrs: inlinehint nounwind sspstrong uwtable
define linkonce_odr dso_local void @_ZN6ResizeD0Ev(%class.Resize* %0) unnamed_addr #5 comdat align 2 !dbg !2704 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2707, metadata !DIExpression()), !dbg !2708
  %2 = bitcast %class.Resize* %0 to %class.Element*, !dbg !2709
  tail call void @_ZN7ElementD2Ev(%class.Element* %2) #11, !dbg !2709
  %3 = bitcast %class.Resize* %0 to i8*, !dbg !2709
  tail call void @_ZdlPv(i8* %3) #12, !dbg !2709
  ret void, !dbg !2709
}

declare void @_ZN7Element4pushEiP6Packet(%class.Element*, i32, %class.Packet*) unnamed_addr #2

declare %class.Packet* @_ZN7Element4pullEi(%class.Element*, i32) unnamed_addr #2

declare zeroext i1 @_ZN7Element8run_taskEP4Task(%class.Element*, %class.Task*) unnamed_addr #2

declare void @_ZN7Element9run_timerEP5Timer(%class.Element*, %class.Timer*) unnamed_addr #2

declare void @_ZN7Element8selectedEii(%class.Element*, i32, i32) unnamed_addr #2

declare void @_ZN7Element8selectedEi(%class.Element*, i32) unnamed_addr #2

; Function Attrs: nounwind sspstrong uwtable
define linkonce_odr dso_local i8* @_ZNK6Resize10class_nameEv(%class.Resize* %0) unnamed_addr #6 comdat align 2 !dbg !2710 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2712, metadata !DIExpression()), !dbg !2714
  ret i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str.4, i64 0, i64 0), !dbg !2715
}

; Function Attrs: nounwind sspstrong uwtable
define linkonce_odr dso_local i8* @_ZNK6Resize10port_countEv(%class.Resize* %0) unnamed_addr #6 comdat align 2 !dbg !2716 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2718, metadata !DIExpression()), !dbg !2719
  ret i8* getelementptr inbounds ([0 x i8], [0 x i8]* @_ZN7Element9PORTS_1_1E, i64 0, i64 0), !dbg !2720
}

declare i8* @_ZNK7Element10processingEv(%class.Element*) unnamed_addr #2

declare i8* @_ZNK7Element9flow_codeEv(%class.Element*) unnamed_addr #2

; Function Attrs: nounwind sspstrong uwtable
define linkonce_odr dso_local i8* @_ZNK6Resize5flagsEv(%class.Resize* %0) unnamed_addr #6 comdat align 2 !dbg !2721 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2723, metadata !DIExpression()), !dbg !2724
  ret i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str.5, i64 0, i64 0), !dbg !2725
}

declare i8* @_ZN7Element4castEPKc(%class.Element*, i8*) unnamed_addr #2

declare i8* @_ZN7Element9port_castEbiPKc(%class.Element*, i1 zeroext, i32, i8*) unnamed_addr #2

declare i32 @_ZNK7Element15configure_phaseEv(%class.Element*) unnamed_addr #2

declare i32 @_ZN7Element10initializeEP12ErrorHandler(%class.Element*, %class.ErrorHandler*) unnamed_addr #2

declare void @_ZN7Element10take_stateEPS_P12ErrorHandler(%class.Element*, %class.Element*, %class.ErrorHandler*) unnamed_addr #2

declare %class.Element* @_ZNK7Element15hotswap_elementEv(%class.Element*) unnamed_addr #2

declare void @_ZN7Element7cleanupENS_12CleanupStageE(%class.Element*, i32) unnamed_addr #2

declare void @_ZNK7Element11declarationEv(%class.String* sret, %class.Element*) unnamed_addr #2

; Function Attrs: nounwind sspstrong uwtable
define linkonce_odr dso_local zeroext i1 @_ZNK6Resize20can_live_reconfigureEv(%class.Resize* %0) unnamed_addr #6 comdat align 2 !dbg !2726 {
  call void @llvm.dbg.value(metadata %class.Resize* %0, metadata !2728, metadata !DIExpression()), !dbg !2729
  ret i1 true, !dbg !2730
}

declare i32 @_ZN7Element16live_reconfigureER6VectorI6StringEP12ErrorHandler(%class.Element*, %class.Vector* dereferenceable(16), %class.ErrorHandler*) unnamed_addr #2

declare i32 @_ZN7Element5llrpcEjPv(%class.Element*, i32, i8*) unnamed_addr #2

declare %class.WritablePacket* @_ZN6Packet14expensive_pushEj(%class.Packet*, i32) local_unnamed_addr #2

declare i8* @_ZNK6Packet4dataEv(%class.Packet*) local_unnamed_addr #2

declare %class.WritablePacket* @_ZN6Packet13expensive_putEj(%class.Packet*, i32) local_unnamed_addr #2

declare i8* @_ZNK6Packet8end_dataEv(%class.Packet*) local_unnamed_addr #2

; Function Attrs: nobuiltin nounwind
declare void @_ZdlPv(i8*) local_unnamed_addr #7

; Function Attrs: noinline optnone sspstrong uwtable
define linkonce_odr dso_local void @_Z14args_base_readIiEvP4ArgsPKciRT_(%class.Args* %0, i8* %1, i32 %2, i32* dereferenceable(4) %3) local_unnamed_addr #8 comdat !dbg !2731 {
  %5 = alloca %class.Args*, align 8
  %6 = alloca i8*, align 8
  %7 = alloca i32, align 4
  %8 = alloca i32*, align 8
  store %class.Args* %0, %class.Args** %5, align 8, !tbaa !2737
  call void @llvm.dbg.declare(metadata %class.Args** %5, metadata !2733, metadata !DIExpression()), !dbg !2738
  store i8* %1, i8** %6, align 8, !tbaa !2737
  call void @llvm.dbg.declare(metadata i8** %6, metadata !2734, metadata !DIExpression()), !dbg !2739
  store i32 %2, i32* %7, align 4, !tbaa !2740
  call void @llvm.dbg.declare(metadata i32* %7, metadata !2735, metadata !DIExpression()), !dbg !2741
  store i32* %3, i32** %8, align 8, !tbaa !2737
  call void @llvm.dbg.declare(metadata i32** %8, metadata !2736, metadata !DIExpression()), !dbg !2742
  %9 = load %class.Args*, %class.Args** %5, align 8, !dbg !2743, !tbaa !2737
  %10 = load i8*, i8** %6, align 8, !dbg !2744, !tbaa !2737
  %11 = load i32, i32* %7, align 4, !dbg !2745, !tbaa !2740
  %12 = load i32*, i32** %8, align 8, !dbg !2746, !tbaa !2737
  call void @_ZN4Args9base_readIiEEvPKciRT_(%class.Args* %9, i8* %10, i32 %11, i32* dereferenceable(4) %12), !dbg !2747
  ret void, !dbg !2748
}

; Function Attrs: sspstrong uwtable
define linkonce_odr dso_local void @_ZN4Args9base_readIiEEvPKciRT_(%class.Args* %0, i8* %1, i32 %2, i32* dereferenceable(4) %3) local_unnamed_addr #0 comdat align 2 personality i8* bitcast (i32 (...)* @__gxx_personality_v0 to i8*) !dbg !2749 {
  %5 = alloca [1 x i32], align 4
  call void @llvm.dbg.declare(metadata [1 x i32]* %5, metadata !1851, metadata !DIExpression()), !dbg !2763
  %6 = alloca i64, align 8
  %7 = alloca %"struct.Args::Slot"*, align 8
  %8 = alloca %class.String, align 8
  call void @llvm.dbg.value(metadata %class.Args* %0, metadata !2754, metadata !DIExpression()), !dbg !2794
  call void @llvm.dbg.value(metadata i8* %1, metadata !2755, metadata !DIExpression()), !dbg !2794
  call void @llvm.dbg.value(metadata i32 %2, metadata !2756, metadata !DIExpression()), !dbg !2794
  call void @llvm.dbg.value(metadata i32* %3, metadata !2757, metadata !DIExpression()), !dbg !2794
  %9 = bitcast %"struct.Args::Slot"** %7 to i8*, !dbg !2795
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %9) #11, !dbg !2795
  %10 = bitcast %class.String* %8 to i8*, !dbg !2796
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %10) #11, !dbg !2796
  call void @llvm.dbg.declare(metadata %class.String* %8, metadata !2759, metadata !DIExpression()), !dbg !2797
  call void @llvm.dbg.value(metadata %"struct.Args::Slot"** %7, metadata !2758, metadata !DIExpression(DW_OP_deref)), !dbg !2794
  call void @_ZN4Args4findEPKciRPNS_4SlotE(%class.String* nonnull sret %8, %class.Args* %0, i8* %1, i32 %2, %"struct.Args::Slot"** nonnull dereferenceable(8) %7), !dbg !2798
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2799, metadata !DIExpression()), !dbg !2802
  %11 = getelementptr inbounds %class.String, %class.String* %8, i64 0, i32 0, i32 1, !dbg !2804
  %12 = load i32, i32* %11, align 8, !dbg !2804, !tbaa !2805
  %13 = icmp eq i32 %12, 0, !dbg !2808
  %14 = select i1 %13, { i64, i64 } zeroinitializer, { i64, i64 } { i64 ptrtoint (i32 (%class.String*)* @_ZNK6String6lengthEv to i64), i64 0 }, !dbg !2809
  %15 = extractvalue { i64, i64 } %14, 0, !dbg !2797
  %16 = icmp eq i64 %15, 0, !dbg !2797
  br i1 %16, label %77, label %17, !dbg !2796

17:                                               ; preds = %4
  call void @llvm.dbg.value(metadata i32* %3, metadata !2810, metadata !DIExpression()), !dbg !2817
  call void @llvm.dbg.value(metadata %class.Args* %0, metadata !2816, metadata !DIExpression()), !dbg !2817
  call void @llvm.dbg.value(metadata %class.Args* %0, metadata !2819, metadata !DIExpression()), !dbg !2826
  call void @llvm.dbg.value(metadata i32* %3, metadata !2825, metadata !DIExpression()), !dbg !2826
  %18 = bitcast i32* %3 to i8*, !dbg !2828
  %19 = invoke i8* @_ZN4Args11simple_slotEPvm(%class.Args* nonnull %0, i8* nonnull %18, i64 4)
          to label %20 unwind label %57, !dbg !2830

20:                                               ; preds = %17
  %21 = bitcast i8* %19 to i32*, !dbg !2831
  call void @llvm.dbg.value(metadata i32* %21, metadata !2761, metadata !DIExpression()), !dbg !2832
  %22 = icmp eq i8* %19, null, !dbg !2833
  br i1 %22, label %54, label %23, !dbg !2834

23:                                               ; preds = %20
  %24 = bitcast i64* %6 to i8*, !dbg !2835
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %24), !dbg !2835
  call void @llvm.dbg.value(metadata i64 0, metadata !2789, metadata !DIExpression()), !dbg !2835
  store i64 0, i64* %6, align 8
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2790, metadata !DIExpression()), !dbg !2835
  call void @llvm.dbg.value(metadata i32* %21, metadata !2791, metadata !DIExpression()), !dbg !2835
  call void @llvm.dbg.value(metadata %class.Args* %0, metadata !2792, metadata !DIExpression()), !dbg !2835
  %25 = bitcast i64* %6 to %class.IntArg*, !dbg !2836
  %26 = bitcast %class.Args* %0 to %class.ArgContext*, !dbg !2837
  call void @llvm.dbg.value(metadata %class.IntArg* %25, metadata !2769, metadata !DIExpression()), !dbg !2838
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2770, metadata !DIExpression()), !dbg !2838
  call void @llvm.dbg.value(metadata i32* %21, metadata !2771, metadata !DIExpression()), !dbg !2838
  call void @llvm.dbg.value(metadata %class.ArgContext* %26, metadata !2772, metadata !DIExpression()), !dbg !2838
  call void @llvm.dbg.value(metadata %class.IntArg* %25, metadata !1844, metadata !DIExpression()), !dbg !2839
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !1846, metadata !DIExpression()), !dbg !2839
  call void @llvm.dbg.value(metadata %class.ArgContext* %26, metadata !1848, metadata !DIExpression()), !dbg !2839
  call void @llvm.dbg.value(metadata i8 1, metadata !1849, metadata !DIExpression()), !dbg !2839
  call void @llvm.dbg.value(metadata i32 1, metadata !1850, metadata !DIExpression()), !dbg !2839
  %27 = bitcast [1 x i32]* %5 to i8*, !dbg !2840
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %27) #11, !dbg !2840
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2841, metadata !DIExpression()), !dbg !2844
  %28 = getelementptr inbounds %class.String, %class.String* %8, i64 0, i32 0, i32 0, !dbg !2847
  %29 = load i8*, i8** %28, align 8, !dbg !2847, !tbaa !2848
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2849, metadata !DIExpression()), !dbg !2852
  %30 = load i32, i32* %11, align 8, !dbg !2854, !tbaa !2805
  %31 = sext i32 %30 to i64, !dbg !2855
  %32 = getelementptr inbounds i8, i8* %29, i64 %31, !dbg !2855
  %33 = getelementptr inbounds [1 x i32], [1 x i32]* %5, i64 0, i64 0, !dbg !2856
  call void @llvm.dbg.value(metadata i64* %6, metadata !2789, metadata !DIExpression(DW_OP_deref)), !dbg !2835
  %34 = invoke i8* @_ZN6IntArg5parseEPKcS1_biPji(%class.IntArg* nonnull %25, i8* %29, i8* %32, i1 zeroext true, i32 4, i32* nonnull %33, i32 1)
          to label %35 unwind label %57, !dbg !2857

35:                                               ; preds = %23
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2849, metadata !DIExpression()), !dbg !2858
  %36 = load i8*, i8** %28, align 8, !dbg !2860, !tbaa !2848
  %37 = load i32, i32* %11, align 8, !dbg !2861, !tbaa !2805
  %38 = sext i32 %37 to i64, !dbg !2862
  %39 = getelementptr inbounds i8, i8* %36, i64 %38, !dbg !2862
  %40 = icmp eq i8* %34, %39, !dbg !2863
  %41 = getelementptr inbounds %class.IntArg, %class.IntArg* %25, i64 0, i32 1, !dbg !2839
  br i1 %40, label %43, label %42, !dbg !2864

42:                                               ; preds = %35
  store i32 22, i32* %41, align 4, !dbg !2865, !tbaa !2866
  br label %45, !dbg !2868

43:                                               ; preds = %35
  %44 = load i32, i32* %41, align 4, !dbg !2870, !tbaa !2866
  switch i32 %44, label %45 [
    i32 0, label %47
    i32 34, label %47
  ], !dbg !2868

45:                                               ; preds = %43, %42
  invoke void (%class.ArgContext*, i8*, ...) @_ZNK10ArgContext5errorEPKcz(%class.ArgContext* nonnull %26, i8* getelementptr inbounds ([15 x i8], [15 x i8]* @.str.6, i64 0, i64 0))
          to label %46 unwind label %57, !dbg !2871

46:                                               ; preds = %45
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %27) #11, !dbg !2873
  br label %52, !dbg !2874

47:                                               ; preds = %43, %43
  call void @llvm.dbg.value(metadata i32* %33, metadata !2875, metadata !DIExpression()), !dbg !2887
  call void @llvm.dbg.value(metadata i32* %33, metadata !2889, metadata !DIExpression()), !dbg !2898
  %48 = load i32, i32* %33, align 4, !dbg !2900, !tbaa !2740
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %27) #11, !dbg !2873
  switch i32 %44, label %52 [
    i32 34, label %49
    i32 0, label %51
  ], !dbg !2901

49:                                               ; preds = %47
  %50 = sext i32 %48 to i64, !dbg !2902
  call void @llvm.dbg.value(metadata i64* %6, metadata !2789, metadata !DIExpression(DW_OP_deref)), !dbg !2835
  invoke void @_ZN6IntArg11range_errorERK10ArgContextbx(%class.IntArg* nonnull %25, %class.ArgContext* nonnull dereferenceable(32) %26, i1 zeroext true, i64 %50)
          to label %52 unwind label %57, !dbg !2905

51:                                               ; preds = %47
  store i32 %48, i32* %21, align 4, !dbg !2906, !tbaa !2740
  br label %52, !dbg !2908

52:                                               ; preds = %49, %46, %47, %51
  %53 = phi i1 [ true, %51 ], [ false, %47 ], [ false, %46 ], [ false, %49 ], !dbg !2909
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %24), !dbg !2910
  br label %54, !dbg !2910

54:                                               ; preds = %52, %20
  %55 = phi i1 [ false, %20 ], [ %53, %52 ], !dbg !2832
  %56 = load %"struct.Args::Slot"*, %"struct.Args::Slot"** %7, align 8, !dbg !2911, !tbaa !2737
  call void @llvm.dbg.value(metadata %"struct.Args::Slot"* %56, metadata !2758, metadata !DIExpression()), !dbg !2794
  invoke void @_ZN4Args9postparseEbPNS_4SlotE(%class.Args* nonnull %0, i1 zeroext %55, %"struct.Args::Slot"* %56)
          to label %77 unwind label %57, !dbg !2912

57:                                               ; preds = %49, %45, %23, %17, %54
  %58 = landingpad { i8*, i32 }
          cleanup, !dbg !2913
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2914, metadata !DIExpression()) #11, !dbg !2917
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2919, metadata !DIExpression()) #11, !dbg !2922
  %59 = getelementptr inbounds %class.String, %class.String* %8, i64 0, i32 0, i32 2, !dbg !2925
  %60 = load %"struct.String::memo_t"*, %"struct.String::memo_t"** %59, align 8, !dbg !2925, !tbaa !2927
  %61 = icmp eq %"struct.String::memo_t"* %60, null, !dbg !2928
  br i1 %61, label %76, label %62, !dbg !2929

62:                                               ; preds = %57
  %63 = getelementptr inbounds %"struct.String::memo_t", %"struct.String::memo_t"* %60, i64 0, i32 0, !dbg !2930
  %64 = load volatile i32, i32* %63, align 4, !dbg !2930, !tbaa !2932
  %65 = icmp eq i32 %64, 0, !dbg !2930
  br i1 %65, label %66, label %67, !dbg !2930

66:                                               ; preds = %62
  call void @__assert_fail(i8* getelementptr inbounds ([18 x i8], [18 x i8]* @.str.7, i64 0, i64 0), i8* getelementptr inbounds ([29 x i8], [29 x i8]* @.str.8, i64 0, i64 0), i32 273, i8* getelementptr inbounds ([27 x i8], [27 x i8]* @__PRETTY_FUNCTION__._ZNK6String5derefEv, i64 0, i64 0)) #13, !dbg !2930
  unreachable, !dbg !2930

67:                                               ; preds = %62
  call void @llvm.dbg.value(metadata i32* %63, metadata !2934, metadata !DIExpression()) #11, !dbg !2937
  %68 = load volatile i32, i32* %63, align 4, !dbg !2940, !tbaa !2740
  %69 = add i32 %68, -1, !dbg !2940
  store volatile i32 %69, i32* %63, align 4, !dbg !2940, !tbaa !2740
  %70 = icmp eq i32 %69, 0, !dbg !2941
  br i1 %70, label %71, label %72, !dbg !2942

71:                                               ; preds = %67
  invoke void @_ZN6String11delete_memoEPNS_6memo_tE(%"struct.String::memo_t"* nonnull %60)
          to label %72 unwind label %73, !dbg !2943

72:                                               ; preds = %71, %67
  store %"struct.String::memo_t"* null, %"struct.String::memo_t"** %59, align 8, !dbg !2944, !tbaa !2927
  br label %76, !dbg !2945

73:                                               ; preds = %71
  %74 = landingpad { i8*, i32 }
          catch i8* null, !dbg !2946
  %75 = extractvalue { i8*, i32 } %74, 0, !dbg !2946
  call void @__clang_call_terminate(i8* %75) #13, !dbg !2946
  unreachable, !dbg !2946

76:                                               ; preds = %57, %72
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %10) #11, !dbg !2796
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %9) #11, !dbg !2947
  resume { i8*, i32 } %58, !dbg !2947

77:                                               ; preds = %54, %4
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2914, metadata !DIExpression()) #11, !dbg !2948
  call void @llvm.dbg.value(metadata %class.String* %8, metadata !2919, metadata !DIExpression()) #11, !dbg !2950
  %78 = getelementptr inbounds %class.String, %class.String* %8, i64 0, i32 0, i32 2, !dbg !2952
  %79 = load %"struct.String::memo_t"*, %"struct.String::memo_t"** %78, align 8, !dbg !2952, !tbaa !2927
  %80 = icmp eq %"struct.String::memo_t"* %79, null, !dbg !2953
  br i1 %80, label %95, label %81, !dbg !2954

81:                                               ; preds = %77
  %82 = getelementptr inbounds %"struct.String::memo_t", %"struct.String::memo_t"* %79, i64 0, i32 0, !dbg !2955
  %83 = load volatile i32, i32* %82, align 4, !dbg !2955, !tbaa !2932
  %84 = icmp eq i32 %83, 0, !dbg !2955
  br i1 %84, label %85, label %86, !dbg !2955

85:                                               ; preds = %81
  call void @__assert_fail(i8* getelementptr inbounds ([18 x i8], [18 x i8]* @.str.7, i64 0, i64 0), i8* getelementptr inbounds ([29 x i8], [29 x i8]* @.str.8, i64 0, i64 0), i32 273, i8* getelementptr inbounds ([27 x i8], [27 x i8]* @__PRETTY_FUNCTION__._ZNK6String5derefEv, i64 0, i64 0)) #13, !dbg !2955
  unreachable, !dbg !2955

86:                                               ; preds = %81
  call void @llvm.dbg.value(metadata i32* %82, metadata !2934, metadata !DIExpression()) #11, !dbg !2956
  %87 = load volatile i32, i32* %82, align 4, !dbg !2958, !tbaa !2740
  %88 = add i32 %87, -1, !dbg !2958
  store volatile i32 %88, i32* %82, align 4, !dbg !2958, !tbaa !2740
  %89 = icmp eq i32 %88, 0, !dbg !2959
  br i1 %89, label %90, label %91, !dbg !2960

90:                                               ; preds = %86
  invoke void @_ZN6String11delete_memoEPNS_6memo_tE(%"struct.String::memo_t"* nonnull %79)
          to label %91 unwind label %92, !dbg !2961

91:                                               ; preds = %90, %86
  store %"struct.String::memo_t"* null, %"struct.String::memo_t"** %78, align 8, !dbg !2962, !tbaa !2927
  br label %95, !dbg !2963

92:                                               ; preds = %90
  %93 = landingpad { i8*, i32 }
          catch i8* null, !dbg !2964
  %94 = extractvalue { i8*, i32 } %93, 0, !dbg !2964
  call void @__clang_call_terminate(i8* %94) #13, !dbg !2964
  unreachable, !dbg !2964

95:                                               ; preds = %77, %91
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %10) #11, !dbg !2796
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %9) #11, !dbg !2947
  ret void, !dbg !2947
}

declare void @_ZN4Args4findEPKciRPNS_4SlotE(%class.String* sret, %class.Args*, i8*, i32, %"struct.Args::Slot"** dereferenceable(8)) local_unnamed_addr #2

declare void @_ZN4Args9postparseEbPNS_4SlotE(%class.Args*, i1 zeroext, %"struct.Args::Slot"*) local_unnamed_addr #2

; Function Attrs: inlinehint nounwind sspstrong uwtable
define linkonce_odr dso_local i32 @_ZNK6String6lengthEv(%class.String* %0) #5 comdat align 2 !dbg !2965 {
  call void @llvm.dbg.value(metadata %class.String* %0, metadata !2967, metadata !DIExpression()), !dbg !2968
  %2 = getelementptr inbounds %class.String, %class.String* %0, i64 0, i32 0, i32 1, !dbg !2969
  %3 = load i32, i32* %2, align 8, !dbg !2969, !tbaa !2805
  ret i32 %3, !dbg !2970
}

declare i8* @_ZN4Args11simple_slotEPvm(%class.Args*, i8*, i64) local_unnamed_addr #2

declare void @_ZN6IntArg11range_errorERK10ArgContextbx(%class.IntArg*, %class.ArgContext* dereferenceable(32), i1 zeroext, i64) local_unnamed_addr #2

declare i8* @_ZN6IntArg5parseEPKcS1_biPji(%class.IntArg*, i8*, i8*, i1 zeroext, i32, i32*, i32) local_unnamed_addr #2

declare void @_ZNK10ArgContext5errorEPKcz(%class.ArgContext*, i8*, ...) local_unnamed_addr #2

; Function Attrs: noinline noreturn nounwind
define linkonce_odr hidden void @__clang_call_terminate(i8* %0) local_unnamed_addr #9 comdat {
  %2 = tail call i8* @__cxa_begin_catch(i8* %0) #11
  tail call void @_ZSt9terminatev() #13
  unreachable
}

declare i8* @__cxa_begin_catch(i8*) local_unnamed_addr

declare void @_ZSt9terminatev() local_unnamed_addr

; Function Attrs: noreturn nounwind
declare void @__assert_fail(i8*, i8*, i32, i8*) local_unnamed_addr #10

declare void @_ZN6String11delete_memoEPNS_6memo_tE(%"struct.String::memo_t"*) local_unnamed_addr #2

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

attributes #0 = { sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable willreturn }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { argmemonly nounwind willreturn }
attributes #4 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { inlinehint nounwind sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #6 = { nounwind sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #7 = { nobuiltin nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #8 = { noinline optnone sspstrong uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #9 = { noinline noreturn nounwind }
attributes #10 = { noreturn nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #11 = { nounwind }
attributes #12 = { builtin nounwind }
attributes #13 = { noreturn nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2489, !2490, !2491, !2492, !2493}
!llvm.ident = !{!2494}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !1, producer: "clang version 10.0.0 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, retainedTypes: !1282, imports: !1869, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "../elements/standard/resize.cc", directory: "/home/john/projects/click/ir-dir")
!2 = !{!3, !857, !1162, !1273}
!3 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "PacketType", scope: !5, file: !4, line: 368, baseType: !16, size: 32, elements: !1154, identifier: "_ZTSN6Packet10PacketTypeE")
!4 = !DIFile(filename: "../dummy_inc/click/packet.hh", directory: "/home/john/projects/click/ir-dir")
!5 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Packet", file: !4, line: 35, size: 1344, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !6, identifier: "_ZTS6Packet")
!6 = !{!7, !77, !79, !82, !83, !84, !85, !128, !136, !137, !226, !229, !232, !235, !238, !242, !246, !249, !252, !257, !258, !261, !262, !263, !264, !265, !266, !269, !272, !275, !276, !279, !280, !283, !286, !287, !288, !289, !292, !295, !298, !301, !302, !303, !306, !307, !308, !311, !312, !313, !314, !315, !316, !317, !318, !319, !320, !321, !322, !323, !324, !325, !326, !331, !334, !339, !340, !341, !344, !349, !350, !351, !354, !357, !362, !367, !372, !377, !381, !898, !902, !905, !911, !914, !917, !920, !923, !927, !930, !931, !932, !933, !1023, !1026, !1027, !1030, !1034, !1039, !1043, !1048, !1051, !1054, !1057, !1060, !1066, !1069, !1072, !1075, !1078, !1081, !1084, !1087, !1090, !1093, !1094, !1097, !1101, !1102, !1103, !1104, !1105, !1106, !1107, !1108, !1109, !1110, !1111, !1112, !1113, !1114, !1115, !1116, !1117, !1118, !1119, !1120, !1121, !1122, !1123, !1124, !1125, !1126, !1127, !1128, !1129, !1130, !1131, !1132, !1133, !1134, !1135, !1138, !1139, !1143, !1146, !1149, !1152, !1153}
!7 = !DIDerivedType(tag: DW_TAG_member, name: "_use_count", scope: !5, file: !4, line: 731, baseType: !8, size: 32)
!8 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "atomic_uint32_t", file: !9, line: 52, size: 32, flags: DIFlagTypePassByValue, elements: !10, identifier: "_ZTS15atomic_uint32_t")
!9 = !DIFile(filename: "../dummy_inc/click/atomic.hh", directory: "/home/john/projects/click/ir-dir")
!10 = !{!11, !17, !22, !23, !28, !35, !36, !37, !38, !41, !44, !45, !46, !49, !50, !54, !57, !60, !65, !68, !71, !74}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "_val", scope: !8, file: !9, line: 91, baseType: !12, size: 32)
!12 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint32_t", file: !13, line: 26, baseType: !14)
!13 = !DIFile(filename: "/usr/include/bits/stdint-uintn.h", directory: "")
!14 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint32_t", file: !15, line: 42, baseType: !16)
!15 = !DIFile(filename: "/usr/include/bits/types.h", directory: "")
!16 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!17 = !DISubprogram(name: "value", linkageName: "_ZNK15atomic_uint32_t5valueEv", scope: !8, file: !9, line: 57, type: !18, scopeLine: 57, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!18 = !DISubroutineType(types: !19)
!19 = !{!12, !20}
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!21 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !8)
!22 = !DISubprogram(name: "operator unsigned int", linkageName: "_ZNK15atomic_uint32_tcvjEv", scope: !8, file: !9, line: 58, type: !18, scopeLine: 58, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!23 = !DISubprogram(name: "operator=", linkageName: "_ZN15atomic_uint32_taSEj", scope: !8, file: !9, line: 60, type: !24, scopeLine: 60, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!24 = !DISubroutineType(types: !25)
!25 = !{!26, !27, !12}
!26 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !8, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !8, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!28 = !DISubprogram(name: "operator+=", linkageName: "_ZN15atomic_uint32_tpLEi", scope: !8, file: !9, line: 62, type: !29, scopeLine: 62, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!29 = !DISubroutineType(types: !30)
!30 = !{!26, !27, !31}
!31 = !DIDerivedType(tag: DW_TAG_typedef, name: "int32_t", file: !32, line: 26, baseType: !33)
!32 = !DIFile(filename: "/usr/include/bits/stdint-intn.h", directory: "")
!33 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int32_t", file: !15, line: 41, baseType: !34)
!34 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!35 = !DISubprogram(name: "operator-=", linkageName: "_ZN15atomic_uint32_tmIEi", scope: !8, file: !9, line: 63, type: !29, scopeLine: 63, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!36 = !DISubprogram(name: "operator|=", linkageName: "_ZN15atomic_uint32_toREj", scope: !8, file: !9, line: 64, type: !24, scopeLine: 64, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!37 = !DISubprogram(name: "operator&=", linkageName: "_ZN15atomic_uint32_taNEj", scope: !8, file: !9, line: 65, type: !24, scopeLine: 65, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!38 = !DISubprogram(name: "operator++", linkageName: "_ZN15atomic_uint32_tppEv", scope: !8, file: !9, line: 67, type: !39, scopeLine: 67, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!39 = !DISubroutineType(types: !40)
!40 = !{null, !27}
!41 = !DISubprogram(name: "operator++", linkageName: "_ZN15atomic_uint32_tppEi", scope: !8, file: !9, line: 68, type: !42, scopeLine: 68, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!42 = !DISubroutineType(types: !43)
!43 = !{null, !27, !34}
!44 = !DISubprogram(name: "operator--", linkageName: "_ZN15atomic_uint32_tmmEv", scope: !8, file: !9, line: 69, type: !39, scopeLine: 69, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!45 = !DISubprogram(name: "operator--", linkageName: "_ZN15atomic_uint32_tmmEi", scope: !8, file: !9, line: 70, type: !42, scopeLine: 70, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!46 = !DISubprogram(name: "swap", linkageName: "_ZN15atomic_uint32_t4swapEj", scope: !8, file: !9, line: 72, type: !47, scopeLine: 72, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!47 = !DISubroutineType(types: !48)
!48 = !{!12, !27, !12}
!49 = !DISubprogram(name: "fetch_and_add", linkageName: "_ZN15atomic_uint32_t13fetch_and_addEj", scope: !8, file: !9, line: 73, type: !47, scopeLine: 73, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!50 = !DISubprogram(name: "dec_and_test", linkageName: "_ZN15atomic_uint32_t12dec_and_testEv", scope: !8, file: !9, line: 74, type: !51, scopeLine: 74, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!51 = !DISubroutineType(types: !52)
!52 = !{!53, !27}
!53 = !DIBasicType(name: "bool", size: 8, encoding: DW_ATE_boolean)
!54 = !DISubprogram(name: "compare_swap", linkageName: "_ZN15atomic_uint32_t12compare_swapEjj", scope: !8, file: !9, line: 75, type: !55, scopeLine: 75, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!55 = !DISubroutineType(types: !56)
!56 = !{!12, !27, !12, !12}
!57 = !DISubprogram(name: "compare_and_swap", linkageName: "_ZN15atomic_uint32_t16compare_and_swapEjj", scope: !8, file: !9, line: 76, type: !58, scopeLine: 76, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!58 = !DISubroutineType(types: !59)
!59 = !{!53, !27, !12, !12}
!60 = !DISubprogram(name: "swap", linkageName: "_ZN15atomic_uint32_t4swapERVjj", scope: !8, file: !9, line: 78, type: !61, scopeLine: 78, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!61 = !DISubroutineType(types: !62)
!62 = !{!12, !63, !12}
!63 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !64, size: 64)
!64 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !12)
!65 = !DISubprogram(name: "inc", linkageName: "_ZN15atomic_uint32_t3incERVj", scope: !8, file: !9, line: 79, type: !66, scopeLine: 79, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!66 = !DISubroutineType(types: !67)
!67 = !{null, !63}
!68 = !DISubprogram(name: "dec_and_test", linkageName: "_ZN15atomic_uint32_t12dec_and_testERVj", scope: !8, file: !9, line: 80, type: !69, scopeLine: 80, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!69 = !DISubroutineType(types: !70)
!70 = !{!53, !63}
!71 = !DISubprogram(name: "compare_swap", linkageName: "_ZN15atomic_uint32_t12compare_swapERVjjj", scope: !8, file: !9, line: 81, type: !72, scopeLine: 81, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!72 = !DISubroutineType(types: !73)
!73 = !{!12, !63, !12, !12}
!74 = !DISubprogram(name: "compare_and_swap", linkageName: "_ZN15atomic_uint32_t16compare_and_swapERVjjj", scope: !8, file: !9, line: 82, type: !75, scopeLine: 82, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!75 = !DISubroutineType(types: !76)
!76 = !{!53, !63, !12, !12}
!77 = !DIDerivedType(tag: DW_TAG_member, name: "_data_packet", scope: !5, file: !4, line: 732, baseType: !78, size: 64, offset: 64)
!78 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !5, size: 64)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "_head", scope: !5, file: !4, line: 734, baseType: !80, size: 64, offset: 128)
!80 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !81, size: 64)
!81 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "_data", scope: !5, file: !4, line: 735, baseType: !80, size: 64, offset: 192)
!83 = !DIDerivedType(tag: DW_TAG_member, name: "_tail", scope: !5, file: !4, line: 736, baseType: !80, size: 64, offset: 256)
!84 = !DIDerivedType(tag: DW_TAG_member, name: "_end", scope: !5, file: !4, line: 737, baseType: !80, size: 64, offset: 320)
!85 = !DIDerivedType(tag: DW_TAG_member, name: "_aa", scope: !5, file: !4, line: 741, baseType: !86, size: 832, offset: 384)
!86 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "AllAnno", scope: !5, file: !4, line: 716, size: 832, flags: DIFlagTypePassByValue, elements: !87, identifier: "_ZTSN6Packet7AllAnnoE")
!87 = !{!88, !118, !119, !120, !121, !122, !126, !127}
!88 = !DIDerivedType(tag: DW_TAG_member, name: "cb", scope: !86, file: !4, line: 717, baseType: !89, size: 384)
!89 = distinct !DICompositeType(tag: DW_TAG_union_type, name: "Anno", scope: !5, file: !4, line: 702, size: 384, flags: DIFlagTypePassByValue, elements: !90, identifier: "_ZTSN6Packet4AnnoE")
!90 = !{!91, !96, !100, !107, !111}
!91 = !DIDerivedType(tag: DW_TAG_member, name: "c", scope: !89, file: !4, line: 703, baseType: !92, size: 384)
!92 = !DICompositeType(tag: DW_TAG_array_type, baseType: !93, size: 384, elements: !94)
!93 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!94 = !{!95}
!95 = !DISubrange(count: 48)
!96 = !DIDerivedType(tag: DW_TAG_member, name: "u8", scope: !89, file: !4, line: 704, baseType: !97, size: 384)
!97 = !DICompositeType(tag: DW_TAG_array_type, baseType: !98, size: 384, elements: !94)
!98 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !13, line: 24, baseType: !99)
!99 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !15, line: 38, baseType: !81)
!100 = !DIDerivedType(tag: DW_TAG_member, name: "u16", scope: !89, file: !4, line: 705, baseType: !101, size: 384)
!101 = !DICompositeType(tag: DW_TAG_array_type, baseType: !102, size: 384, elements: !105)
!102 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint16_t", file: !13, line: 25, baseType: !103)
!103 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !15, line: 40, baseType: !104)
!104 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!105 = !{!106}
!106 = !DISubrange(count: 24)
!107 = !DIDerivedType(tag: DW_TAG_member, name: "u32", scope: !89, file: !4, line: 706, baseType: !108, size: 384)
!108 = !DICompositeType(tag: DW_TAG_array_type, baseType: !12, size: 384, elements: !109)
!109 = !{!110}
!110 = !DISubrange(count: 12)
!111 = !DIDerivedType(tag: DW_TAG_member, name: "u64", scope: !89, file: !4, line: 708, baseType: !112, size: 384)
!112 = !DICompositeType(tag: DW_TAG_array_type, baseType: !113, size: 384, elements: !116)
!113 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint64_t", file: !13, line: 27, baseType: !114)
!114 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint64_t", file: !15, line: 45, baseType: !115)
!115 = !DIBasicType(name: "long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!116 = !{!117}
!117 = !DISubrange(count: 6)
!118 = !DIDerivedType(tag: DW_TAG_member, name: "mac", scope: !86, file: !4, line: 718, baseType: !80, size: 64, offset: 384)
!119 = !DIDerivedType(tag: DW_TAG_member, name: "nh", scope: !86, file: !4, line: 719, baseType: !80, size: 64, offset: 448)
!120 = !DIDerivedType(tag: DW_TAG_member, name: "h", scope: !86, file: !4, line: 720, baseType: !80, size: 64, offset: 512)
!121 = !DIDerivedType(tag: DW_TAG_member, name: "pkt_type", scope: !86, file: !4, line: 721, baseType: !3, size: 32, offset: 576)
!122 = !DIDerivedType(tag: DW_TAG_member, name: "timestamp", scope: !86, file: !4, line: 722, baseType: !123, size: 64, offset: 608)
!123 = !DICompositeType(tag: DW_TAG_array_type, baseType: !93, size: 64, elements: !124)
!124 = !{!125}
!125 = !DISubrange(count: 8)
!126 = !DIDerivedType(tag: DW_TAG_member, name: "next", scope: !86, file: !4, line: 723, baseType: !78, size: 64, offset: 704)
!127 = !DIDerivedType(tag: DW_TAG_member, name: "prev", scope: !86, file: !4, line: 724, baseType: !78, size: 64, offset: 768)
!128 = !DIDerivedType(tag: DW_TAG_member, name: "_destructor", scope: !5, file: !4, line: 746, baseType: !129, size: 64, offset: 1216)
!129 = !DIDerivedType(tag: DW_TAG_typedef, name: "buffer_destructor_type", scope: !5, file: !4, line: 65, baseType: !130)
!130 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !131, size: 64)
!131 = !DISubroutineType(types: !132)
!132 = !{null, !80, !133, !135}
!133 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !134, line: 46, baseType: !115)
!134 = !DIFile(filename: "/usr/lib/clang/10.0.0/include/stddef.h", directory: "")
!135 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!136 = !DIDerivedType(tag: DW_TAG_member, name: "_destructor_argument", scope: !5, file: !4, line: 747, baseType: !135, size: 64, offset: 1280)
!137 = !DISubprogram(name: "make", linkageName: "_ZN6Packet4makeEjPKvjj", scope: !5, file: !4, line: 52, type: !138, scopeLine: 52, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!138 = !DISubroutineType(types: !139)
!139 = !{!140, !12, !224, !12, !12}
!140 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !141, size: 64)
!141 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "WritablePacket", file: !4, line: 778, size: 1344, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !142, identifier: "_ZTS14WritablePacket")
!142 = !{!143, !144, !149, !150, !151, !152, !153, !158, !159, !182, !187, !188, !193, !198, !203, !204, !208, !209, !214, !215, !218, !221}
!143 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !141, baseType: !5, flags: DIFlagPublic, extraData: i32 0)
!144 = !DISubprogram(name: "data", linkageName: "_ZNK14WritablePacket4dataEv", scope: !141, file: !4, line: 780, type: !145, scopeLine: 780, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!145 = !DISubroutineType(types: !146)
!146 = !{!80, !147}
!147 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !148, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!148 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !141)
!149 = !DISubprogram(name: "end_data", linkageName: "_ZNK14WritablePacket8end_dataEv", scope: !141, file: !4, line: 781, type: !145, scopeLine: 781, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!150 = !DISubprogram(name: "buffer", linkageName: "_ZNK14WritablePacket6bufferEv", scope: !141, file: !4, line: 782, type: !145, scopeLine: 782, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!151 = !DISubprogram(name: "end_buffer", linkageName: "_ZNK14WritablePacket10end_bufferEv", scope: !141, file: !4, line: 783, type: !145, scopeLine: 783, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!152 = !DISubprogram(name: "mac_header", linkageName: "_ZNK14WritablePacket10mac_headerEv", scope: !141, file: !4, line: 784, type: !145, scopeLine: 784, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!153 = !DISubprogram(name: "ether_header", linkageName: "_ZNK14WritablePacket12ether_headerEv", scope: !141, file: !4, line: 785, type: !154, scopeLine: 785, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!154 = !DISubroutineType(types: !155)
!155 = !{!156, !147}
!156 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !157, size: 64)
!157 = !DICompositeType(tag: DW_TAG_structure_type, name: "click_ether", file: !4, line: 24, flags: DIFlagFwdDecl, identifier: "_ZTS11click_ether")
!158 = !DISubprogram(name: "network_header", linkageName: "_ZNK14WritablePacket14network_headerEv", scope: !141, file: !4, line: 786, type: !145, scopeLine: 786, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!159 = !DISubprogram(name: "ip_header", linkageName: "_ZNK14WritablePacket9ip_headerEv", scope: !141, file: !4, line: 787, type: !160, scopeLine: 787, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!160 = !DISubroutineType(types: !161)
!161 = !{!162, !147}
!162 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !163, size: 64)
!163 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "click_ip", file: !164, line: 23, size: 160, flags: DIFlagTypePassByValue, elements: !165, identifier: "_ZTS8click_ip")
!164 = !DIFile(filename: "../dummy_inc/clicknet/ip.h", directory: "/home/john/projects/click/ir-dir")
!165 = !{!166, !167, !168, !169, !170, !171, !172, !173, !174, !175, !181}
!166 = !DIDerivedType(tag: DW_TAG_member, name: "ip_hl", scope: !163, file: !164, line: 28, baseType: !16, size: 4, flags: DIFlagBitField, extraData: i64 0)
!167 = !DIDerivedType(tag: DW_TAG_member, name: "ip_v", scope: !163, file: !164, line: 29, baseType: !16, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!168 = !DIDerivedType(tag: DW_TAG_member, name: "ip_tos", scope: !163, file: !164, line: 33, baseType: !98, size: 8, offset: 8)
!169 = !DIDerivedType(tag: DW_TAG_member, name: "ip_len", scope: !163, file: !164, line: 40, baseType: !102, size: 16, offset: 16)
!170 = !DIDerivedType(tag: DW_TAG_member, name: "ip_id", scope: !163, file: !164, line: 41, baseType: !102, size: 16, offset: 32)
!171 = !DIDerivedType(tag: DW_TAG_member, name: "ip_off", scope: !163, file: !164, line: 42, baseType: !102, size: 16, offset: 48)
!172 = !DIDerivedType(tag: DW_TAG_member, name: "ip_ttl", scope: !163, file: !164, line: 47, baseType: !98, size: 8, offset: 64)
!173 = !DIDerivedType(tag: DW_TAG_member, name: "ip_p", scope: !163, file: !164, line: 48, baseType: !98, size: 8, offset: 72)
!174 = !DIDerivedType(tag: DW_TAG_member, name: "ip_sum", scope: !163, file: !164, line: 49, baseType: !102, size: 16, offset: 80)
!175 = !DIDerivedType(tag: DW_TAG_member, name: "ip_src", scope: !163, file: !164, line: 50, baseType: !176, size: 32, offset: 96)
!176 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in_addr", file: !177, line: 31, size: 32, flags: DIFlagTypePassByValue, elements: !178, identifier: "_ZTS7in_addr")
!177 = !DIFile(filename: "/usr/include/netinet/in.h", directory: "")
!178 = !{!179}
!179 = !DIDerivedType(tag: DW_TAG_member, name: "s_addr", scope: !176, file: !177, line: 33, baseType: !180, size: 32)
!180 = !DIDerivedType(tag: DW_TAG_typedef, name: "in_addr_t", file: !177, line: 30, baseType: !12)
!181 = !DIDerivedType(tag: DW_TAG_member, name: "ip_dst", scope: !163, file: !164, line: 51, baseType: !176, size: 32, offset: 128)
!182 = !DISubprogram(name: "ip6_header", linkageName: "_ZNK14WritablePacket10ip6_headerEv", scope: !141, file: !4, line: 788, type: !183, scopeLine: 788, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!183 = !DISubroutineType(types: !184)
!184 = !{!185, !147}
!185 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !186, size: 64)
!186 = !DICompositeType(tag: DW_TAG_structure_type, name: "click_ip6", file: !4, line: 27, flags: DIFlagFwdDecl, identifier: "_ZTS9click_ip6")
!187 = !DISubprogram(name: "transport_header", linkageName: "_ZNK14WritablePacket16transport_headerEv", scope: !141, file: !4, line: 789, type: !145, scopeLine: 789, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!188 = !DISubprogram(name: "icmp_header", linkageName: "_ZNK14WritablePacket11icmp_headerEv", scope: !141, file: !4, line: 790, type: !189, scopeLine: 790, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!189 = !DISubroutineType(types: !190)
!190 = !{!191, !147}
!191 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !192, size: 64)
!192 = !DICompositeType(tag: DW_TAG_structure_type, name: "click_icmp", file: !4, line: 26, flags: DIFlagFwdDecl, identifier: "_ZTS10click_icmp")
!193 = !DISubprogram(name: "tcp_header", linkageName: "_ZNK14WritablePacket10tcp_headerEv", scope: !141, file: !4, line: 791, type: !194, scopeLine: 791, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!194 = !DISubroutineType(types: !195)
!195 = !{!196, !147}
!196 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !197, size: 64)
!197 = !DICompositeType(tag: DW_TAG_structure_type, name: "click_tcp", file: !4, line: 28, flags: DIFlagFwdDecl, identifier: "_ZTS9click_tcp")
!198 = !DISubprogram(name: "udp_header", linkageName: "_ZNK14WritablePacket10udp_headerEv", scope: !141, file: !4, line: 792, type: !199, scopeLine: 792, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!199 = !DISubroutineType(types: !200)
!200 = !{!201, !147}
!201 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !202, size: 64)
!202 = !DICompositeType(tag: DW_TAG_structure_type, name: "click_udp", file: !4, line: 29, flags: DIFlagFwdDecl, identifier: "_ZTS9click_udp")
!203 = !DISubprogram(name: "buffer_data", linkageName: "_ZNK14WritablePacket11buffer_dataEv", scope: !141, file: !4, line: 795, type: !145, scopeLine: 795, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!204 = !DISubprogram(name: "WritablePacket", scope: !141, file: !4, line: 800, type: !205, scopeLine: 800, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!205 = !DISubroutineType(types: !206)
!206 = !{null, !207}
!207 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !141, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!208 = !DISubprogram(name: "initialize", linkageName: "_ZN14WritablePacket10initializeEv", scope: !141, file: !4, line: 802, type: !205, scopeLine: 802, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!209 = !DISubprogram(name: "WritablePacket", scope: !141, file: !4, line: 804, type: !210, scopeLine: 804, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!210 = !DISubroutineType(types: !211)
!211 = !{null, !207, !212}
!212 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !213, size: 64)
!213 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !5)
!214 = !DISubprogram(name: "~WritablePacket", scope: !141, file: !4, line: 805, type: !205, scopeLine: 805, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!215 = !DISubprogram(name: "pool_allocate", linkageName: "_ZN14WritablePacket13pool_allocateEb", scope: !141, file: !4, line: 808, type: !216, scopeLine: 808, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!216 = !DISubroutineType(types: !217)
!217 = !{!140, !53}
!218 = !DISubprogram(name: "pool_allocate", linkageName: "_ZN14WritablePacket13pool_allocateEjjj", scope: !141, file: !4, line: 809, type: !219, scopeLine: 809, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!219 = !DISubroutineType(types: !220)
!220 = !{!140, !12, !12, !12}
!221 = !DISubprogram(name: "recycle", linkageName: "_ZN14WritablePacket7recycleEPS_", scope: !141, file: !4, line: 811, type: !222, scopeLine: 811, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!222 = !DISubroutineType(types: !223)
!223 = !{null, !140}
!224 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !225, size: 64)
!225 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!226 = !DISubprogram(name: "make", linkageName: "_ZN6Packet4makeEPKvj", scope: !5, file: !4, line: 54, type: !227, scopeLine: 54, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!227 = !DISubroutineType(types: !228)
!228 = !{!140, !224, !12}
!229 = !DISubprogram(name: "make", linkageName: "_ZN6Packet4makeEj", scope: !5, file: !4, line: 55, type: !230, scopeLine: 55, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!230 = !DISubroutineType(types: !231)
!231 = !{!140, !12}
!232 = !DISubprogram(name: "make", linkageName: "_ZN6Packet4makeEPhjPFvS0_mPvES1_ii", scope: !5, file: !4, line: 66, type: !233, scopeLine: 66, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!233 = !DISubroutineType(types: !234)
!234 = !{!140, !80, !12, !129, !135, !34, !34}
!235 = !DISubprogram(name: "static_cleanup", linkageName: "_ZN6Packet14static_cleanupEv", scope: !5, file: !4, line: 71, type: !236, scopeLine: 71, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!236 = !DISubroutineType(types: !237)
!237 = !{null}
!238 = !DISubprogram(name: "kill", linkageName: "_ZN6Packet4killEv", scope: !5, file: !4, line: 73, type: !239, scopeLine: 73, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!239 = !DISubroutineType(types: !240)
!240 = !{null, !241}
!241 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !5, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!242 = !DISubprogram(name: "shared", linkageName: "_ZNK6Packet6sharedEv", scope: !5, file: !4, line: 75, type: !243, scopeLine: 75, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!243 = !DISubroutineType(types: !244)
!244 = !{!53, !245}
!245 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !213, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!246 = !DISubprogram(name: "clone", linkageName: "_ZN6Packet5cloneEv", scope: !5, file: !4, line: 76, type: !247, scopeLine: 76, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!247 = !DISubroutineType(types: !248)
!248 = !{!78, !241}
!249 = !DISubprogram(name: "uniqueify", linkageName: "_ZN6Packet9uniqueifyEv", scope: !5, file: !4, line: 77, type: !250, scopeLine: 77, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!250 = !DISubroutineType(types: !251)
!251 = !{!140, !241}
!252 = !DISubprogram(name: "data", linkageName: "_ZNK6Packet4dataEv", scope: !5, file: !4, line: 79, type: !253, scopeLine: 79, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!253 = !DISubroutineType(types: !254)
!254 = !{!255, !245}
!255 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !256, size: 64)
!256 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !81)
!257 = !DISubprogram(name: "end_data", linkageName: "_ZNK6Packet8end_dataEv", scope: !5, file: !4, line: 80, type: !253, scopeLine: 80, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!258 = !DISubprogram(name: "length", linkageName: "_ZNK6Packet6lengthEv", scope: !5, file: !4, line: 81, type: !259, scopeLine: 81, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!259 = !DISubroutineType(types: !260)
!260 = !{!12, !245}
!261 = !DISubprogram(name: "headroom", linkageName: "_ZNK6Packet8headroomEv", scope: !5, file: !4, line: 82, type: !259, scopeLine: 82, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!262 = !DISubprogram(name: "tailroom", linkageName: "_ZNK6Packet8tailroomEv", scope: !5, file: !4, line: 83, type: !259, scopeLine: 83, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!263 = !DISubprogram(name: "buffer", linkageName: "_ZNK6Packet6bufferEv", scope: !5, file: !4, line: 84, type: !253, scopeLine: 84, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!264 = !DISubprogram(name: "end_buffer", linkageName: "_ZNK6Packet10end_bufferEv", scope: !5, file: !4, line: 85, type: !253, scopeLine: 85, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!265 = !DISubprogram(name: "buffer_length", linkageName: "_ZNK6Packet13buffer_lengthEv", scope: !5, file: !4, line: 86, type: !259, scopeLine: 86, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!266 = !DISubprogram(name: "buffer_destructor", linkageName: "_ZNK6Packet17buffer_destructorEv", scope: !5, file: !4, line: 97, type: !267, scopeLine: 97, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!267 = !DISubroutineType(types: !268)
!268 = !{!129, !245}
!269 = !DISubprogram(name: "set_buffer_destructor", linkageName: "_ZN6Packet21set_buffer_destructorEPFvPhmPvE", scope: !5, file: !4, line: 101, type: !270, scopeLine: 101, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!270 = !DISubroutineType(types: !271)
!271 = !{null, !241, !129}
!272 = !DISubprogram(name: "destructor_argument", linkageName: "_ZN6Packet19destructor_argumentEv", scope: !5, file: !4, line: 105, type: !273, scopeLine: 105, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!273 = !DISubroutineType(types: !274)
!274 = !{!135, !241}
!275 = !DISubprogram(name: "reset_buffer", linkageName: "_ZN6Packet12reset_bufferEv", scope: !5, file: !4, line: 109, type: !239, scopeLine: 109, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!276 = !DISubprogram(name: "push", linkageName: "_ZN6Packet4pushEj", scope: !5, file: !4, line: 141, type: !277, scopeLine: 141, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!277 = !DISubroutineType(types: !278)
!278 = !{!140, !241, !12}
!279 = !DISubprogram(name: "push_mac_header", linkageName: "_ZN6Packet15push_mac_headerEj", scope: !5, file: !4, line: 152, type: !277, scopeLine: 152, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!280 = !DISubprogram(name: "nonunique_push", linkageName: "_ZN6Packet14nonunique_pushEj", scope: !5, file: !4, line: 171, type: !281, scopeLine: 171, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!281 = !DISubroutineType(types: !282)
!282 = !{!78, !241, !12}
!283 = !DISubprogram(name: "pull", linkageName: "_ZN6Packet4pullEj", scope: !5, file: !4, line: 187, type: !284, scopeLine: 187, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!284 = !DISubroutineType(types: !285)
!285 = !{null, !241, !12}
!286 = !DISubprogram(name: "put", linkageName: "_ZN6Packet3putEj", scope: !5, file: !4, line: 213, type: !277, scopeLine: 213, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!287 = !DISubprogram(name: "nonunique_put", linkageName: "_ZN6Packet13nonunique_putEj", scope: !5, file: !4, line: 230, type: !281, scopeLine: 230, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!288 = !DISubprogram(name: "take", linkageName: "_ZN6Packet4takeEj", scope: !5, file: !4, line: 245, type: !284, scopeLine: 245, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!289 = !DISubprogram(name: "shift_data", linkageName: "_ZN6Packet10shift_dataEib", scope: !5, file: !4, line: 269, type: !290, scopeLine: 269, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!290 = !DISubroutineType(types: !291)
!291 = !{!78, !241, !34, !53}
!292 = !DISubprogram(name: "shrink_data", linkageName: "_ZN6Packet11shrink_dataEPKhj", scope: !5, file: !4, line: 271, type: !293, scopeLine: 271, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!293 = !DISubroutineType(types: !294)
!294 = !{null, !241, !255, !12}
!295 = !DISubprogram(name: "change_headroom_and_length", linkageName: "_ZN6Packet26change_headroom_and_lengthEjj", scope: !5, file: !4, line: 272, type: !296, scopeLine: 272, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!296 = !DISubroutineType(types: !297)
!297 = !{null, !241, !12, !12}
!298 = !DISubprogram(name: "copy", linkageName: "_ZN6Packet4copyEPS_i", scope: !5, file: !4, line: 274, type: !299, scopeLine: 274, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!299 = !DISubroutineType(types: !300)
!300 = !{!53, !241, !78, !34}
!301 = !DISubprogram(name: "has_mac_header", linkageName: "_ZNK6Packet14has_mac_headerEv", scope: !5, file: !4, line: 279, type: !243, scopeLine: 279, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!302 = !DISubprogram(name: "mac_header", linkageName: "_ZNK6Packet10mac_headerEv", scope: !5, file: !4, line: 280, type: !253, scopeLine: 280, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!303 = !DISubprogram(name: "mac_header_offset", linkageName: "_ZNK6Packet17mac_header_offsetEv", scope: !5, file: !4, line: 281, type: !304, scopeLine: 281, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!304 = !DISubroutineType(types: !305)
!305 = !{!34, !245}
!306 = !DISubprogram(name: "mac_header_length", linkageName: "_ZNK6Packet17mac_header_lengthEv", scope: !5, file: !4, line: 282, type: !259, scopeLine: 282, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!307 = !DISubprogram(name: "mac_length", linkageName: "_ZNK6Packet10mac_lengthEv", scope: !5, file: !4, line: 283, type: !304, scopeLine: 283, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!308 = !DISubprogram(name: "set_mac_header", linkageName: "_ZN6Packet14set_mac_headerEPKh", scope: !5, file: !4, line: 284, type: !309, scopeLine: 284, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!309 = !DISubroutineType(types: !310)
!310 = !{null, !241, !255}
!311 = !DISubprogram(name: "set_mac_header", linkageName: "_ZN6Packet14set_mac_headerEPKhj", scope: !5, file: !4, line: 285, type: !293, scopeLine: 285, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!312 = !DISubprogram(name: "clear_mac_header", linkageName: "_ZN6Packet16clear_mac_headerEv", scope: !5, file: !4, line: 286, type: !239, scopeLine: 286, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!313 = !DISubprogram(name: "has_network_header", linkageName: "_ZNK6Packet18has_network_headerEv", scope: !5, file: !4, line: 288, type: !243, scopeLine: 288, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!314 = !DISubprogram(name: "network_header", linkageName: "_ZNK6Packet14network_headerEv", scope: !5, file: !4, line: 289, type: !253, scopeLine: 289, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!315 = !DISubprogram(name: "network_header_offset", linkageName: "_ZNK6Packet21network_header_offsetEv", scope: !5, file: !4, line: 290, type: !304, scopeLine: 290, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!316 = !DISubprogram(name: "network_header_length", linkageName: "_ZNK6Packet21network_header_lengthEv", scope: !5, file: !4, line: 291, type: !259, scopeLine: 291, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!317 = !DISubprogram(name: "network_length", linkageName: "_ZNK6Packet14network_lengthEv", scope: !5, file: !4, line: 292, type: !304, scopeLine: 292, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!318 = !DISubprogram(name: "set_network_header", linkageName: "_ZN6Packet18set_network_headerEPKhj", scope: !5, file: !4, line: 293, type: !293, scopeLine: 293, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!319 = !DISubprogram(name: "set_network_header_length", linkageName: "_ZN6Packet25set_network_header_lengthEj", scope: !5, file: !4, line: 294, type: !284, scopeLine: 294, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!320 = !DISubprogram(name: "clear_network_header", linkageName: "_ZN6Packet20clear_network_headerEv", scope: !5, file: !4, line: 295, type: !239, scopeLine: 295, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!321 = !DISubprogram(name: "has_transport_header", linkageName: "_ZNK6Packet20has_transport_headerEv", scope: !5, file: !4, line: 297, type: !243, scopeLine: 297, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!322 = !DISubprogram(name: "transport_header", linkageName: "_ZNK6Packet16transport_headerEv", scope: !5, file: !4, line: 298, type: !253, scopeLine: 298, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!323 = !DISubprogram(name: "transport_header_offset", linkageName: "_ZNK6Packet23transport_header_offsetEv", scope: !5, file: !4, line: 299, type: !304, scopeLine: 299, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!324 = !DISubprogram(name: "transport_length", linkageName: "_ZNK6Packet16transport_lengthEv", scope: !5, file: !4, line: 300, type: !304, scopeLine: 300, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!325 = !DISubprogram(name: "clear_transport_header", linkageName: "_ZN6Packet22clear_transport_headerEv", scope: !5, file: !4, line: 301, type: !239, scopeLine: 301, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!326 = !DISubprogram(name: "ether_header", linkageName: "_ZNK6Packet12ether_headerEv", scope: !5, file: !4, line: 304, type: !327, scopeLine: 304, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!327 = !DISubroutineType(types: !328)
!328 = !{!329, !245}
!329 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !330, size: 64)
!330 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !157)
!331 = !DISubprogram(name: "set_ether_header", linkageName: "_ZN6Packet16set_ether_headerEPK11click_ether", scope: !5, file: !4, line: 305, type: !332, scopeLine: 305, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!332 = !DISubroutineType(types: !333)
!333 = !{null, !241, !329}
!334 = !DISubprogram(name: "ip_header", linkageName: "_ZNK6Packet9ip_headerEv", scope: !5, file: !4, line: 307, type: !335, scopeLine: 307, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!335 = !DISubroutineType(types: !336)
!336 = !{!337, !245}
!337 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !338, size: 64)
!338 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !163)
!339 = !DISubprogram(name: "ip_header_offset", linkageName: "_ZNK6Packet16ip_header_offsetEv", scope: !5, file: !4, line: 308, type: !304, scopeLine: 308, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!340 = !DISubprogram(name: "ip_header_length", linkageName: "_ZNK6Packet16ip_header_lengthEv", scope: !5, file: !4, line: 309, type: !259, scopeLine: 309, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!341 = !DISubprogram(name: "set_ip_header", linkageName: "_ZN6Packet13set_ip_headerEPK8click_ipj", scope: !5, file: !4, line: 310, type: !342, scopeLine: 310, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!342 = !DISubroutineType(types: !343)
!343 = !{null, !241, !337, !12}
!344 = !DISubprogram(name: "ip6_header", linkageName: "_ZNK6Packet10ip6_headerEv", scope: !5, file: !4, line: 312, type: !345, scopeLine: 312, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!345 = !DISubroutineType(types: !346)
!346 = !{!347, !245}
!347 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !348, size: 64)
!348 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !186)
!349 = !DISubprogram(name: "ip6_header_offset", linkageName: "_ZNK6Packet17ip6_header_offsetEv", scope: !5, file: !4, line: 313, type: !304, scopeLine: 313, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!350 = !DISubprogram(name: "ip6_header_length", linkageName: "_ZNK6Packet17ip6_header_lengthEv", scope: !5, file: !4, line: 314, type: !259, scopeLine: 314, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!351 = !DISubprogram(name: "set_ip6_header", linkageName: "_ZN6Packet14set_ip6_headerEPK9click_ip6", scope: !5, file: !4, line: 315, type: !352, scopeLine: 315, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!352 = !DISubroutineType(types: !353)
!353 = !{null, !241, !347}
!354 = !DISubprogram(name: "set_ip6_header", linkageName: "_ZN6Packet14set_ip6_headerEPK9click_ip6j", scope: !5, file: !4, line: 316, type: !355, scopeLine: 316, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!355 = !DISubroutineType(types: !356)
!356 = !{null, !241, !347, !12}
!357 = !DISubprogram(name: "icmp_header", linkageName: "_ZNK6Packet11icmp_headerEv", scope: !5, file: !4, line: 318, type: !358, scopeLine: 318, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!358 = !DISubroutineType(types: !359)
!359 = !{!360, !245}
!360 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !361, size: 64)
!361 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !192)
!362 = !DISubprogram(name: "tcp_header", linkageName: "_ZNK6Packet10tcp_headerEv", scope: !5, file: !4, line: 319, type: !363, scopeLine: 319, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!363 = !DISubroutineType(types: !364)
!364 = !{!365, !245}
!365 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !366, size: 64)
!366 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !197)
!367 = !DISubprogram(name: "udp_header", linkageName: "_ZNK6Packet10udp_headerEv", scope: !5, file: !4, line: 320, type: !368, scopeLine: 320, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!368 = !DISubroutineType(types: !369)
!369 = !{!370, !245}
!370 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !371, size: 64)
!371 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !202)
!372 = !DISubprogram(name: "xanno", linkageName: "_ZNK6Packet5xannoEv", scope: !5, file: !4, line: 340, type: !373, scopeLine: 340, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!373 = !DISubroutineType(types: !374)
!374 = !{!375, !245}
!375 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !376, size: 64)
!376 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !89)
!377 = !DISubprogram(name: "xanno", linkageName: "_ZN6Packet5xannoEv", scope: !5, file: !4, line: 341, type: !378, scopeLine: 341, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!378 = !DISubroutineType(types: !379)
!379 = !{!380, !241}
!380 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !89, size: 64)
!381 = !DISubprogram(name: "timestamp_anno", linkageName: "_ZNK6Packet14timestamp_annoEv", scope: !5, file: !4, line: 354, type: !382, scopeLine: 354, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!382 = !DISubroutineType(types: !383)
!383 = !{!384, !245}
!384 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !385, size: 64)
!385 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !386)
!386 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Timestamp", file: !387, line: 122, size: 64, flags: DIFlagTypePassByValue | DIFlagNonTrivial, elements: !388, identifier: "_ZTS9Timestamp")
!387 = !DIFile(filename: "../dummy_inc/click/timestamp.hh", directory: "/home/john/projects/click/ir-dir")
!388 = !{!389, !396, !400, !403, !406, !409, !412, !416, !428, !439, !444, !453, !462, !465, !466, !469, !470, !471, !472, !475, !478, !479, !480, !481, !484, !485, !488, !491, !495, !496, !497, !500, !501, !502, !507, !511, !514, !517, !520, !523, !524, !525, !526, !527, !530, !531, !534, !535, !536, !537, !538, !539, !540, !543, !544, !545, !546, !547, !548, !549, !550, !551, !841, !842, !845, !846, !847, !848, !849, !850, !851, !854, !863, !866, !867, !870, !873, !874, !875, !876, !877, !878, !879, !882, !886, !889, !892, !895}
!389 = !DIDerivedType(tag: DW_TAG_member, name: "_t", scope: !386, file: !387, line: 672, baseType: !390, size: 64)
!390 = distinct !DICompositeType(tag: DW_TAG_union_type, name: "rep_t", scope: !386, file: !387, line: 539, size: 64, flags: DIFlagTypePassByValue, elements: !391, identifier: "_ZTSN9Timestamp5rep_tE")
!391 = !{!392}
!392 = !DIDerivedType(tag: DW_TAG_member, name: "x", scope: !390, file: !387, line: 541, baseType: !393, size: 64)
!393 = !DIDerivedType(tag: DW_TAG_typedef, name: "int64_t", file: !32, line: 27, baseType: !394)
!394 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int64_t", file: !15, line: 44, baseType: !395)
!395 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!396 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 174, type: !397, scopeLine: 174, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!397 = !DISubroutineType(types: !398)
!398 = !{null, !399}
!399 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !386, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!400 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 187, type: !401, scopeLine: 187, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!401 = !DISubroutineType(types: !402)
!402 = !{null, !399, !395, !12}
!403 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 191, type: !404, scopeLine: 191, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!404 = !DISubroutineType(types: !405)
!405 = !{null, !399, !34, !12}
!406 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 195, type: !407, scopeLine: 195, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!407 = !DISubroutineType(types: !408)
!408 = !{null, !399, !115, !12}
!409 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 199, type: !410, scopeLine: 199, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!410 = !DISubroutineType(types: !411)
!411 = !{null, !399, !16, !12}
!412 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 203, type: !413, scopeLine: 203, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!413 = !DISubroutineType(types: !414)
!414 = !{null, !399, !415}
!415 = !DIBasicType(name: "double", size: 64, encoding: DW_ATE_float)
!416 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 206, type: !417, scopeLine: 206, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!417 = !DISubroutineType(types: !418)
!418 = !{null, !399, !419}
!419 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !420, size: 64)
!420 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !421)
!421 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "timeval", file: !422, line: 8, size: 128, flags: DIFlagTypePassByValue, elements: !423, identifier: "_ZTS7timeval")
!422 = !DIFile(filename: "/usr/include/bits/types/struct_timeval.h", directory: "")
!423 = !{!424, !426}
!424 = !DIDerivedType(tag: DW_TAG_member, name: "tv_sec", scope: !421, file: !422, line: 10, baseType: !425, size: 64)
!425 = !DIDerivedType(tag: DW_TAG_typedef, name: "__time_t", file: !15, line: 160, baseType: !395)
!426 = !DIDerivedType(tag: DW_TAG_member, name: "tv_usec", scope: !421, file: !422, line: 11, baseType: !427, size: 64, offset: 64)
!427 = !DIDerivedType(tag: DW_TAG_typedef, name: "__suseconds_t", file: !15, line: 162, baseType: !395)
!428 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 208, type: !429, scopeLine: 208, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!429 = !DISubroutineType(types: !430)
!430 = !{null, !399, !431}
!431 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !432, size: 64)
!432 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !433)
!433 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "timespec", file: !434, line: 10, size: 128, flags: DIFlagTypePassByValue, elements: !435, identifier: "_ZTS8timespec")
!434 = !DIFile(filename: "/usr/include/bits/types/struct_timespec.h", directory: "")
!435 = !{!436, !437}
!436 = !DIDerivedType(tag: DW_TAG_member, name: "tv_sec", scope: !433, file: !434, line: 12, baseType: !425, size: 64)
!437 = !DIDerivedType(tag: DW_TAG_member, name: "tv_nsec", scope: !433, file: !434, line: 16, baseType: !438, size: 64, offset: 64)
!438 = !DIDerivedType(tag: DW_TAG_typedef, name: "__syscall_slong_t", file: !15, line: 196, baseType: !395)
!439 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 212, type: !440, scopeLine: 212, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!440 = !DISubroutineType(types: !441)
!441 = !{null, !399, !442}
!442 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !443, size: 64)
!443 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !390)
!444 = !DISubprogram(name: "Timestamp", scope: !386, file: !387, line: 217, type: !445, scopeLine: 217, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!445 = !DISubroutineType(types: !446)
!446 = !{null, !399, !447}
!447 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !448, size: 64)
!448 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !449)
!449 = !DIDerivedType(tag: DW_TAG_typedef, name: "uninitialized_t", scope: !386, file: !387, line: 168, baseType: !450)
!450 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "uninitialized_type", file: !451, line: 317, size: 8, flags: DIFlagTypePassByValue, elements: !452, identifier: "_ZTS18uninitialized_type")
!451 = !DIFile(filename: "../dummy_inc/click/config.h", directory: "/home/john/projects/click/ir-dir")
!452 = !{}
!453 = !DISubprogram(name: "operator int (Timestamp::*)() const", linkageName: "_ZNK9TimestampcvMS_KFivEEv", scope: !386, file: !387, line: 222, type: !454, scopeLine: 222, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!454 = !DISubroutineType(types: !455)
!455 = !{!456, !461}
!456 = !DIDerivedType(tag: DW_TAG_typedef, name: "unspecified_bool_type", scope: !386, file: !387, line: 221, baseType: !457)
!457 = !DIDerivedType(tag: DW_TAG_ptr_to_member_type, baseType: !458, size: 128, extraData: !386)
!458 = !DISubroutineType(types: !459)
!459 = !{!460, !461}
!460 = !DIDerivedType(tag: DW_TAG_typedef, name: "seconds_type", scope: !386, file: !387, line: 125, baseType: !31)
!461 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !385, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!462 = !DISubprogram(name: "is_negative", linkageName: "_ZNK9Timestamp11is_negativeEv", scope: !386, file: !387, line: 225, type: !463, scopeLine: 225, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!463 = !DISubroutineType(types: !464)
!464 = !{!53, !461}
!465 = !DISubprogram(name: "sec", linkageName: "_ZNK9Timestamp3secEv", scope: !386, file: !387, line: 233, type: !458, scopeLine: 233, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!466 = !DISubprogram(name: "subsec", linkageName: "_ZNK9Timestamp6subsecEv", scope: !386, file: !387, line: 234, type: !467, scopeLine: 234, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!467 = !DISubroutineType(types: !468)
!468 = !{!12, !461}
!469 = !DISubprogram(name: "msec", linkageName: "_ZNK9Timestamp4msecEv", scope: !386, file: !387, line: 235, type: !467, scopeLine: 235, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!470 = !DISubprogram(name: "usec", linkageName: "_ZNK9Timestamp4usecEv", scope: !386, file: !387, line: 236, type: !467, scopeLine: 236, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!471 = !DISubprogram(name: "nsec", linkageName: "_ZNK9Timestamp4nsecEv", scope: !386, file: !387, line: 237, type: !467, scopeLine: 237, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!472 = !DISubprogram(name: "set_sec", linkageName: "_ZN9Timestamp7set_secEi", scope: !386, file: !387, line: 239, type: !473, scopeLine: 239, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!473 = !DISubroutineType(types: !474)
!474 = !{null, !399, !460}
!475 = !DISubprogram(name: "set_subsec", linkageName: "_ZN9Timestamp10set_subsecEj", scope: !386, file: !387, line: 240, type: !476, scopeLine: 240, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!476 = !DISubroutineType(types: !477)
!477 = !{null, !399, !12}
!478 = !DISubprogram(name: "msec1", linkageName: "_ZNK9Timestamp5msec1Ev", scope: !386, file: !387, line: 242, type: !458, scopeLine: 242, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!479 = !DISubprogram(name: "usec1", linkageName: "_ZNK9Timestamp5usec1Ev", scope: !386, file: !387, line: 243, type: !458, scopeLine: 243, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!480 = !DISubprogram(name: "nsec1", linkageName: "_ZNK9Timestamp5nsec1Ev", scope: !386, file: !387, line: 244, type: !458, scopeLine: 244, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!481 = !DISubprogram(name: "timeval", linkageName: "_ZNK9Timestamp7timevalEv", scope: !386, file: !387, line: 250, type: !482, scopeLine: 250, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!482 = !DISubroutineType(types: !483)
!483 = !{!421, !461}
!484 = !DISubprogram(name: "timeval_ceil", linkageName: "_ZNK9Timestamp12timeval_ceilEv", scope: !386, file: !387, line: 251, type: !482, scopeLine: 251, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!485 = !DISubprogram(name: "timespec", linkageName: "_ZNK9Timestamp8timespecEv", scope: !386, file: !387, line: 257, type: !486, scopeLine: 257, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!486 = !DISubroutineType(types: !487)
!487 = !{!433, !461}
!488 = !DISubprogram(name: "doubleval", linkageName: "_ZNK9Timestamp9doublevalEv", scope: !386, file: !387, line: 262, type: !489, scopeLine: 262, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!489 = !DISubroutineType(types: !490)
!490 = !{!415, !461}
!491 = !DISubprogram(name: "msecval", linkageName: "_ZNK9Timestamp7msecvalEv", scope: !386, file: !387, line: 265, type: !492, scopeLine: 265, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!492 = !DISubroutineType(types: !493)
!493 = !{!494, !461}
!494 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !386, file: !387, line: 128, baseType: !393)
!495 = !DISubprogram(name: "usecval", linkageName: "_ZNK9Timestamp7usecvalEv", scope: !386, file: !387, line: 273, type: !492, scopeLine: 273, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!496 = !DISubprogram(name: "nsecval", linkageName: "_ZNK9Timestamp7nsecvalEv", scope: !386, file: !387, line: 281, type: !492, scopeLine: 281, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!497 = !DISubprogram(name: "msec_ceil", linkageName: "_ZNK9Timestamp9msec_ceilEv", scope: !386, file: !387, line: 290, type: !498, scopeLine: 290, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!498 = !DISubroutineType(types: !499)
!499 = !{!386, !461}
!500 = !DISubprogram(name: "usec_ceil", linkageName: "_ZNK9Timestamp9usec_ceilEv", scope: !386, file: !387, line: 295, type: !498, scopeLine: 295, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!501 = !DISubprogram(name: "nsec_ceil", linkageName: "_ZNK9Timestamp9nsec_ceilEv", scope: !386, file: !387, line: 304, type: !498, scopeLine: 304, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!502 = !DISubprogram(name: "make_jiffies", linkageName: "_ZN9Timestamp12make_jiffiesEj", scope: !386, file: !387, line: 310, type: !503, scopeLine: 310, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!503 = !DISubroutineType(types: !504)
!504 = !{!386, !505}
!505 = !DIDerivedType(tag: DW_TAG_typedef, name: "click_jiffies_t", file: !506, line: 477, baseType: !16)
!506 = !DIFile(filename: "../dummy_inc/click/glue.hh", directory: "/home/john/projects/click/ir-dir")
!507 = !DISubprogram(name: "make_jiffies", linkageName: "_ZN9Timestamp12make_jiffiesEi", scope: !386, file: !387, line: 312, type: !508, scopeLine: 312, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!508 = !DISubroutineType(types: !509)
!509 = !{!386, !510}
!510 = !DIDerivedType(tag: DW_TAG_typedef, name: "click_jiffies_difference_t", file: !506, line: 478, baseType: !34)
!511 = !DISubprogram(name: "jiffies", linkageName: "_ZNK9Timestamp7jiffiesEv", scope: !386, file: !387, line: 314, type: !512, scopeLine: 314, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!512 = !DISubroutineType(types: !513)
!513 = !{!505, !461}
!514 = !DISubprogram(name: "make_sec", linkageName: "_ZN9Timestamp8make_secEi", scope: !386, file: !387, line: 318, type: !515, scopeLine: 318, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!515 = !DISubroutineType(types: !516)
!516 = !{!386, !460}
!517 = !DISubprogram(name: "make_msec", linkageName: "_ZN9Timestamp9make_msecEij", scope: !386, file: !387, line: 324, type: !518, scopeLine: 324, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!518 = !DISubroutineType(types: !519)
!519 = !{!386, !460, !12}
!520 = !DISubprogram(name: "make_msec", linkageName: "_ZN9Timestamp9make_msecEl", scope: !386, file: !387, line: 328, type: !521, scopeLine: 328, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!521 = !DISubroutineType(types: !522)
!522 = !{!386, !494}
!523 = !DISubprogram(name: "make_usec", linkageName: "_ZN9Timestamp9make_usecEij", scope: !386, file: !387, line: 341, type: !518, scopeLine: 341, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!524 = !DISubprogram(name: "make_usec", linkageName: "_ZN9Timestamp9make_usecEl", scope: !386, file: !387, line: 345, type: !521, scopeLine: 345, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!525 = !DISubprogram(name: "make_nsec", linkageName: "_ZN9Timestamp9make_nsecEij", scope: !386, file: !387, line: 358, type: !518, scopeLine: 358, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!526 = !DISubprogram(name: "make_nsec", linkageName: "_ZN9Timestamp9make_nsecEl", scope: !386, file: !387, line: 362, type: !521, scopeLine: 362, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!527 = !DISubprogram(name: "epsilon", linkageName: "_ZN9Timestamp7epsilonEv", scope: !386, file: !387, line: 375, type: !528, scopeLine: 375, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!528 = !DISubroutineType(types: !529)
!529 = !{!386}
!530 = !DISubprogram(name: "clear", linkageName: "_ZN9Timestamp5clearEv", scope: !386, file: !387, line: 380, type: !397, scopeLine: 380, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!531 = !DISubprogram(name: "assign", linkageName: "_ZN9Timestamp6assignEij", scope: !386, file: !387, line: 388, type: !532, scopeLine: 388, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!532 = !DISubroutineType(types: !533)
!533 = !{null, !399, !460, !12}
!534 = !DISubprogram(name: "assign_usec", linkageName: "_ZN9Timestamp11assign_usecEij", scope: !386, file: !387, line: 397, type: !532, scopeLine: 397, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!535 = !DISubprogram(name: "assign_nsec", linkageName: "_ZN9Timestamp11assign_nsecEij", scope: !386, file: !387, line: 401, type: !532, scopeLine: 401, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!536 = !DISubprogram(name: "set", linkageName: "_ZN9Timestamp3setEij", scope: !386, file: !387, line: 408, type: !532, scopeLine: 408, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!537 = !DISubprogram(name: "set_usec", linkageName: "_ZN9Timestamp8set_usecEij", scope: !386, file: !387, line: 411, type: !532, scopeLine: 411, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!538 = !DISubprogram(name: "set_nsec", linkageName: "_ZN9Timestamp8set_nsecEij", scope: !386, file: !387, line: 414, type: !532, scopeLine: 414, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!539 = !DISubprogram(name: "set_now", linkageName: "_ZN9Timestamp7set_nowEv", scope: !386, file: !387, line: 417, type: !397, scopeLine: 417, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!540 = !DISubprogram(name: "set_timeval_ioctl", linkageName: "_ZN9Timestamp17set_timeval_ioctlEii", scope: !386, file: !387, line: 420, type: !541, scopeLine: 420, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!541 = !DISubroutineType(types: !542)
!542 = !{!34, !399, !34, !34}
!543 = !DISubprogram(name: "now", linkageName: "_ZN9Timestamp3nowEv", scope: !386, file: !387, line: 432, type: !528, scopeLine: 432, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!544 = !DISubprogram(name: "assign_now", linkageName: "_ZN9Timestamp10assign_nowEv", scope: !386, file: !387, line: 438, type: !397, scopeLine: 438, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!545 = !DISubprogram(name: "recent", linkageName: "_ZN9Timestamp6recentEv", scope: !386, file: !387, line: 446, type: !528, scopeLine: 446, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!546 = !DISubprogram(name: "assign_recent", linkageName: "_ZN9Timestamp13assign_recentEv", scope: !386, file: !387, line: 452, type: !397, scopeLine: 452, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!547 = !DISubprogram(name: "now_steady", linkageName: "_ZN9Timestamp10now_steadyEv", scope: !386, file: !387, line: 466, type: !528, scopeLine: 466, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!548 = !DISubprogram(name: "assign_now_steady", linkageName: "_ZN9Timestamp17assign_now_steadyEv", scope: !386, file: !387, line: 472, type: !397, scopeLine: 472, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!549 = !DISubprogram(name: "recent_steady", linkageName: "_ZN9Timestamp13recent_steadyEv", scope: !386, file: !387, line: 481, type: !528, scopeLine: 481, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!550 = !DISubprogram(name: "assign_recent_steady", linkageName: "_ZN9Timestamp20assign_recent_steadyEv", scope: !386, file: !387, line: 487, type: !397, scopeLine: 487, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!551 = !DISubprogram(name: "unparse", linkageName: "_ZNK9Timestamp7unparseEv", scope: !386, file: !387, line: 496, type: !552, scopeLine: 496, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!552 = !DISubroutineType(types: !553)
!553 = !{!554, !461}
!554 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "String", file: !555, line: 19, size: 192, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !556, identifier: "_ZTS6String")
!555 = !DIFile(filename: "../dummy_inc/click/string.hh", directory: "/home/john/projects/click/ir-dir")
!556 = !{!557, !562, !576, !577, !581, !585, !587, !588, !592, !597, !601, !604, !607, !610, !613, !616, !619, !622, !625, !628, !631, !634, !637, !641, !645, !648, !649, !652, !655, !656, !659, !662, !665, !669, !673, !677, !680, !681, !686, !689, !690, !694, !695, !698, !699, !702, !703, !706, !709, !712, !715, !718, !721, !724, !727, !730, !733, !736, !739, !740, !741, !742, !745, !748, !749, !750, !751, !752, !753, !754, !758, !761, !764, !767, !768, !769, !770, !771, !772, !775, !779, !780, !781, !782, !785, !786, !787, !788, !789, !790, !793, !794, !795, !796, !799, !802, !803, !806, !809, !812, !815, !818, !821, !824, !825, !826, !827, !830, !833, !836, !837, !838}
!557 = !DIDerivedType(tag: DW_TAG_member, name: "bool_data", scope: !554, file: !555, line: 184, baseType: !558, flags: DIFlagPublic | DIFlagStaticMember)
!558 = !DICompositeType(tag: DW_TAG_array_type, baseType: !559, size: 88, elements: !560)
!559 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !93)
!560 = !{!561}
!561 = !DISubrange(count: 11)
!562 = !DIDerivedType(tag: DW_TAG_member, name: "_r", scope: !554, file: !555, line: 211, baseType: !563, size: 192)
!563 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "rep_t", scope: !554, file: !555, line: 204, size: 192, flags: DIFlagTypePassByValue, elements: !564, identifier: "_ZTSN6String5rep_tE")
!564 = !{!565, !567, !568}
!565 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !563, file: !555, line: 205, baseType: !566, size: 64)
!566 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !559, size: 64)
!567 = !DIDerivedType(tag: DW_TAG_member, name: "length", scope: !563, file: !555, line: 206, baseType: !34, size: 32, offset: 64)
!568 = !DIDerivedType(tag: DW_TAG_member, name: "memo", scope: !563, file: !555, line: 207, baseType: !569, size: 64, offset: 128)
!569 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !570, size: 64)
!570 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "memo_t", scope: !554, file: !555, line: 189, size: 160, flags: DIFlagTypePassByValue, elements: !571, identifier: "_ZTSN6String6memo_tE")
!571 = !{!572, !573, !574, !575}
!572 = !DIDerivedType(tag: DW_TAG_member, name: "refcount", scope: !570, file: !555, line: 190, baseType: !64, size: 32)
!573 = !DIDerivedType(tag: DW_TAG_member, name: "capacity", scope: !570, file: !555, line: 191, baseType: !12, size: 32, offset: 32)
!574 = !DIDerivedType(tag: DW_TAG_member, name: "dirty", scope: !570, file: !555, line: 192, baseType: !64, size: 32, offset: 64)
!575 = !DIDerivedType(tag: DW_TAG_member, name: "real_data", scope: !570, file: !555, line: 197, baseType: !123, size: 64, offset: 96)
!576 = !DIDerivedType(tag: DW_TAG_member, name: "null_data", scope: !554, file: !555, line: 292, baseType: !559, flags: DIFlagStaticMember)
!577 = !DIDerivedType(tag: DW_TAG_member, name: "oom_data", scope: !554, file: !555, line: 293, baseType: !578, flags: DIFlagStaticMember)
!578 = !DICompositeType(tag: DW_TAG_array_type, baseType: !559, size: 120, elements: !579)
!579 = !{!580}
!580 = !DISubrange(count: 15)
!581 = !DIDerivedType(tag: DW_TAG_member, name: "int_data", scope: !554, file: !555, line: 294, baseType: !582, flags: DIFlagStaticMember)
!582 = !DICompositeType(tag: DW_TAG_array_type, baseType: !559, size: 160, elements: !583)
!583 = !{!584}
!584 = !DISubrange(count: 20)
!585 = !DIDerivedType(tag: DW_TAG_member, name: "null_string_rep", scope: !554, file: !555, line: 295, baseType: !586, flags: DIFlagStaticMember)
!586 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !563)
!587 = !DIDerivedType(tag: DW_TAG_member, name: "oom_string_rep", scope: !554, file: !555, line: 296, baseType: !586, flags: DIFlagStaticMember)
!588 = !DISubprogram(name: "String", scope: !554, file: !555, line: 39, type: !589, scopeLine: 39, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!589 = !DISubroutineType(types: !590)
!590 = !{null, !591}
!591 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !554, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!592 = !DISubprogram(name: "String", scope: !554, file: !555, line: 40, type: !593, scopeLine: 40, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!593 = !DISubroutineType(types: !594)
!594 = !{null, !591, !595}
!595 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !596, size: 64)
!596 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !554)
!597 = !DISubprogram(name: "String", scope: !554, file: !555, line: 42, type: !598, scopeLine: 42, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!598 = !DISubroutineType(types: !599)
!599 = !{null, !591, !600}
!600 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !554, size: 64)
!601 = !DISubprogram(name: "String", scope: !554, file: !555, line: 44, type: !602, scopeLine: 44, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!602 = !DISubroutineType(types: !603)
!603 = !{null, !591, !566}
!604 = !DISubprogram(name: "String", scope: !554, file: !555, line: 45, type: !605, scopeLine: 45, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!605 = !DISubroutineType(types: !606)
!606 = !{null, !591, !566, !34}
!607 = !DISubprogram(name: "String", scope: !554, file: !555, line: 46, type: !608, scopeLine: 46, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!608 = !DISubroutineType(types: !609)
!609 = !{null, !591, !255, !34}
!610 = !DISubprogram(name: "String", scope: !554, file: !555, line: 47, type: !611, scopeLine: 47, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!611 = !DISubroutineType(types: !612)
!612 = !{null, !591, !566, !566}
!613 = !DISubprogram(name: "String", scope: !554, file: !555, line: 48, type: !614, scopeLine: 48, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!614 = !DISubroutineType(types: !615)
!615 = !{null, !591, !255, !255}
!616 = !DISubprogram(name: "String", scope: !554, file: !555, line: 49, type: !617, scopeLine: 49, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!617 = !DISubroutineType(types: !618)
!618 = !{null, !591, !53}
!619 = !DISubprogram(name: "String", scope: !554, file: !555, line: 50, type: !620, scopeLine: 50, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!620 = !DISubroutineType(types: !621)
!621 = !{null, !591, !93}
!622 = !DISubprogram(name: "String", scope: !554, file: !555, line: 51, type: !623, scopeLine: 51, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!623 = !DISubroutineType(types: !624)
!624 = !{null, !591, !81}
!625 = !DISubprogram(name: "String", scope: !554, file: !555, line: 52, type: !626, scopeLine: 52, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!626 = !DISubroutineType(types: !627)
!627 = !{null, !591, !34}
!628 = !DISubprogram(name: "String", scope: !554, file: !555, line: 53, type: !629, scopeLine: 53, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!629 = !DISubroutineType(types: !630)
!630 = !{null, !591, !16}
!631 = !DISubprogram(name: "String", scope: !554, file: !555, line: 54, type: !632, scopeLine: 54, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!632 = !DISubroutineType(types: !633)
!633 = !{null, !591, !395}
!634 = !DISubprogram(name: "String", scope: !554, file: !555, line: 55, type: !635, scopeLine: 55, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!635 = !DISubroutineType(types: !636)
!636 = !{null, !591, !115}
!637 = !DISubprogram(name: "String", scope: !554, file: !555, line: 57, type: !638, scopeLine: 57, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!638 = !DISubroutineType(types: !639)
!639 = !{null, !591, !640}
!640 = !DIBasicType(name: "long long int", size: 64, encoding: DW_ATE_signed)
!641 = !DISubprogram(name: "String", scope: !554, file: !555, line: 58, type: !642, scopeLine: 58, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!642 = !DISubroutineType(types: !643)
!643 = !{null, !591, !644}
!644 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!645 = !DISubprogram(name: "String", scope: !554, file: !555, line: 65, type: !646, scopeLine: 65, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!646 = !DISubroutineType(types: !647)
!647 = !{null, !591, !415}
!648 = !DISubprogram(name: "~String", scope: !554, file: !555, line: 67, type: !589, scopeLine: 67, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!649 = !DISubprogram(name: "make_empty", linkageName: "_ZN6String10make_emptyEv", scope: !554, file: !555, line: 69, type: !650, scopeLine: 69, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!650 = !DISubroutineType(types: !651)
!651 = !{!595}
!652 = !DISubprogram(name: "make_uninitialized", linkageName: "_ZN6String18make_uninitializedEi", scope: !554, file: !555, line: 70, type: !653, scopeLine: 70, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!653 = !DISubroutineType(types: !654)
!654 = !{!554, !34}
!655 = !DISubprogram(name: "make_garbage", linkageName: "_ZN6String12make_garbageEi", scope: !554, file: !555, line: 71, type: !653, scopeLine: 71, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!656 = !DISubprogram(name: "make_stable", linkageName: "_ZN6String11make_stableEPKc", scope: !554, file: !555, line: 72, type: !657, scopeLine: 72, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!657 = !DISubroutineType(types: !658)
!658 = !{!554, !566}
!659 = !DISubprogram(name: "make_stable", linkageName: "_ZN6String11make_stableEPKci", scope: !554, file: !555, line: 73, type: !660, scopeLine: 73, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!660 = !DISubroutineType(types: !661)
!661 = !{!554, !566, !34}
!662 = !DISubprogram(name: "make_stable", linkageName: "_ZN6String11make_stableEPKcS1_", scope: !554, file: !555, line: 74, type: !663, scopeLine: 74, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!663 = !DISubroutineType(types: !664)
!664 = !{!554, !566, !566}
!665 = !DISubprogram(name: "make_numeric", linkageName: "_ZN6String12make_numericElib", scope: !554, file: !555, line: 75, type: !666, scopeLine: 75, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!666 = !DISubroutineType(types: !667)
!667 = !{!554, !668, !34, !53}
!668 = !DIDerivedType(tag: DW_TAG_typedef, name: "intmax_t", scope: !554, file: !555, line: 27, baseType: !393)
!669 = !DISubprogram(name: "make_numeric", linkageName: "_ZN6String12make_numericEmib", scope: !554, file: !555, line: 76, type: !670, scopeLine: 76, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!670 = !DISubroutineType(types: !671)
!671 = !{!554, !672, !34, !53}
!672 = !DIDerivedType(tag: DW_TAG_typedef, name: "uintmax_t", scope: !554, file: !555, line: 28, baseType: !113)
!673 = !DISubprogram(name: "data", linkageName: "_ZNK6String4dataEv", scope: !554, file: !555, line: 78, type: !674, scopeLine: 78, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!674 = !DISubroutineType(types: !675)
!675 = !{!566, !676}
!676 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !596, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!677 = !DISubprogram(name: "length", linkageName: "_ZNK6String6lengthEv", scope: !554, file: !555, line: 79, type: !678, scopeLine: 79, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!678 = !DISubroutineType(types: !679)
!679 = !{!34, !676}
!680 = !DISubprogram(name: "c_str", linkageName: "_ZNK6String5c_strEv", scope: !554, file: !555, line: 81, type: !674, scopeLine: 81, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!681 = !DISubprogram(name: "operator int (String::*)() const", linkageName: "_ZNK6StringcvMS_KFivEEv", scope: !554, file: !555, line: 83, type: !682, scopeLine: 83, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!682 = !DISubroutineType(types: !683)
!683 = !{!684, !676}
!684 = !DIDerivedType(tag: DW_TAG_typedef, name: "unspecified_bool_type", scope: !554, file: !555, line: 24, baseType: !685)
!685 = !DIDerivedType(tag: DW_TAG_ptr_to_member_type, baseType: !678, size: 128, extraData: !554)
!686 = !DISubprogram(name: "empty", linkageName: "_ZNK6String5emptyEv", scope: !554, file: !555, line: 84, type: !687, scopeLine: 84, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!687 = !DISubroutineType(types: !688)
!688 = !{!53, !676}
!689 = !DISubprogram(name: "operator!", linkageName: "_ZNK6StringntEv", scope: !554, file: !555, line: 85, type: !687, scopeLine: 85, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!690 = !DISubprogram(name: "begin", linkageName: "_ZNK6String5beginEv", scope: !554, file: !555, line: 87, type: !691, scopeLine: 87, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!691 = !DISubroutineType(types: !692)
!692 = !{!693, !676}
!693 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_iterator", scope: !554, file: !555, line: 21, baseType: !566)
!694 = !DISubprogram(name: "end", linkageName: "_ZNK6String3endEv", scope: !554, file: !555, line: 88, type: !691, scopeLine: 88, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!695 = !DISubprogram(name: "operator[]", linkageName: "_ZNK6StringixEi", scope: !554, file: !555, line: 90, type: !696, scopeLine: 90, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!696 = !DISubroutineType(types: !697)
!697 = !{!93, !676, !34}
!698 = !DISubprogram(name: "at", linkageName: "_ZNK6String2atEi", scope: !554, file: !555, line: 91, type: !696, scopeLine: 91, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!699 = !DISubprogram(name: "front", linkageName: "_ZNK6String5frontEv", scope: !554, file: !555, line: 92, type: !700, scopeLine: 92, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!700 = !DISubroutineType(types: !701)
!701 = !{!93, !676}
!702 = !DISubprogram(name: "back", linkageName: "_ZNK6String4backEv", scope: !554, file: !555, line: 93, type: !700, scopeLine: 93, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!703 = !DISubprogram(name: "hashcode", linkageName: "_ZN6String8hashcodeEPKcS1_", scope: !554, file: !555, line: 95, type: !704, scopeLine: 95, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!704 = !DISubroutineType(types: !705)
!705 = !{!12, !566, !566}
!706 = !DISubprogram(name: "hashcode", linkageName: "_ZN6String8hashcodeEPKhS1_", scope: !554, file: !555, line: 96, type: !707, scopeLine: 96, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!707 = !DISubroutineType(types: !708)
!708 = !{!12, !255, !255}
!709 = !DISubprogram(name: "hashcode", linkageName: "_ZNK6String8hashcodeEv", scope: !554, file: !555, line: 98, type: !710, scopeLine: 98, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!710 = !DISubroutineType(types: !711)
!711 = !{!12, !676}
!712 = !DISubprogram(name: "substring", linkageName: "_ZNK6String9substringEPKcS1_", scope: !554, file: !555, line: 100, type: !713, scopeLine: 100, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!713 = !DISubroutineType(types: !714)
!714 = !{!554, !676, !566, !566}
!715 = !DISubprogram(name: "substring", linkageName: "_ZNK6String9substringEii", scope: !554, file: !555, line: 101, type: !716, scopeLine: 101, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!716 = !DISubroutineType(types: !717)
!717 = !{!554, !676, !34, !34}
!718 = !DISubprogram(name: "substring", linkageName: "_ZNK6String9substringEi", scope: !554, file: !555, line: 102, type: !719, scopeLine: 102, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!719 = !DISubroutineType(types: !720)
!720 = !{!554, !676, !34}
!721 = !DISubprogram(name: "trim_space", linkageName: "_ZNK6String10trim_spaceEv", scope: !554, file: !555, line: 103, type: !722, scopeLine: 103, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!722 = !DISubroutineType(types: !723)
!723 = !{!554, !676}
!724 = !DISubprogram(name: "equals", linkageName: "_ZNK6String6equalsERKS_", scope: !554, file: !555, line: 105, type: !725, scopeLine: 105, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!725 = !DISubroutineType(types: !726)
!726 = !{!53, !676, !595}
!727 = !DISubprogram(name: "equals", linkageName: "_ZNK6String6equalsEPKci", scope: !554, file: !555, line: 106, type: !728, scopeLine: 106, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!728 = !DISubroutineType(types: !729)
!729 = !{!53, !676, !566, !34}
!730 = !DISubprogram(name: "compare", linkageName: "_ZN6String7compareERKS_S1_", scope: !554, file: !555, line: 107, type: !731, scopeLine: 107, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!731 = !DISubroutineType(types: !732)
!732 = !{!34, !595, !595}
!733 = !DISubprogram(name: "compare", linkageName: "_ZNK6String7compareERKS_", scope: !554, file: !555, line: 108, type: !734, scopeLine: 108, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!734 = !DISubroutineType(types: !735)
!735 = !{!34, !676, !595}
!736 = !DISubprogram(name: "compare", linkageName: "_ZNK6String7compareEPKci", scope: !554, file: !555, line: 109, type: !737, scopeLine: 109, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!737 = !DISubroutineType(types: !738)
!738 = !{!34, !676, !566, !34}
!739 = !DISubprogram(name: "starts_with", linkageName: "_ZNK6String11starts_withERKS_", scope: !554, file: !555, line: 110, type: !725, scopeLine: 110, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!740 = !DISubprogram(name: "starts_with", linkageName: "_ZNK6String11starts_withEPKci", scope: !554, file: !555, line: 111, type: !728, scopeLine: 111, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!741 = !DISubprogram(name: "glob_match", linkageName: "_ZNK6String10glob_matchERKS_", scope: !554, file: !555, line: 112, type: !725, scopeLine: 112, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!742 = !DISubprogram(name: "find_left", linkageName: "_ZNK6String9find_leftEci", scope: !554, file: !555, line: 125, type: !743, scopeLine: 125, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!743 = !DISubroutineType(types: !744)
!744 = !{!34, !676, !93, !34}
!745 = !DISubprogram(name: "find_left", linkageName: "_ZNK6String9find_leftERKS_i", scope: !554, file: !555, line: 126, type: !746, scopeLine: 126, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!746 = !DISubroutineType(types: !747)
!747 = !{!34, !676, !595, !34}
!748 = !DISubprogram(name: "find_right", linkageName: "_ZNK6String10find_rightEci", scope: !554, file: !555, line: 127, type: !743, scopeLine: 127, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!749 = !DISubprogram(name: "lower", linkageName: "_ZNK6String5lowerEv", scope: !554, file: !555, line: 129, type: !722, scopeLine: 129, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!750 = !DISubprogram(name: "upper", linkageName: "_ZNK6String5upperEv", scope: !554, file: !555, line: 130, type: !722, scopeLine: 130, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!751 = !DISubprogram(name: "printable", linkageName: "_ZNK6String9printableEv", scope: !554, file: !555, line: 131, type: !722, scopeLine: 131, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!752 = !DISubprogram(name: "quoted_hex", linkageName: "_ZNK6String10quoted_hexEv", scope: !554, file: !555, line: 132, type: !722, scopeLine: 132, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!753 = !DISubprogram(name: "encode_json", linkageName: "_ZNK6String11encode_jsonEv", scope: !554, file: !555, line: 133, type: !722, scopeLine: 133, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!754 = !DISubprogram(name: "operator=", linkageName: "_ZN6StringaSERKS_", scope: !554, file: !555, line: 135, type: !755, scopeLine: 135, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!755 = !DISubroutineType(types: !756)
!756 = !{!757, !591, !595}
!757 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !554, size: 64)
!758 = !DISubprogram(name: "operator=", linkageName: "_ZN6StringaSEOS_", scope: !554, file: !555, line: 137, type: !759, scopeLine: 137, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!759 = !DISubroutineType(types: !760)
!760 = !{!757, !591, !600}
!761 = !DISubprogram(name: "operator=", linkageName: "_ZN6StringaSEPKc", scope: !554, file: !555, line: 139, type: !762, scopeLine: 139, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!762 = !DISubroutineType(types: !763)
!763 = !{!757, !591, !566}
!764 = !DISubprogram(name: "swap", linkageName: "_ZN6String4swapERS_", scope: !554, file: !555, line: 141, type: !765, scopeLine: 141, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!765 = !DISubroutineType(types: !766)
!766 = !{null, !591, !757}
!767 = !DISubprogram(name: "append", linkageName: "_ZN6String6appendERKS_", scope: !554, file: !555, line: 143, type: !593, scopeLine: 143, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!768 = !DISubprogram(name: "append", linkageName: "_ZN6String6appendEPKc", scope: !554, file: !555, line: 144, type: !602, scopeLine: 144, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!769 = !DISubprogram(name: "append", linkageName: "_ZN6String6appendEPKci", scope: !554, file: !555, line: 145, type: !605, scopeLine: 145, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!770 = !DISubprogram(name: "append", linkageName: "_ZN6String6appendEPKcS1_", scope: !554, file: !555, line: 146, type: !611, scopeLine: 146, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!771 = !DISubprogram(name: "append", linkageName: "_ZN6String6appendEc", scope: !554, file: !555, line: 147, type: !620, scopeLine: 147, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!772 = !DISubprogram(name: "append_fill", linkageName: "_ZN6String11append_fillEii", scope: !554, file: !555, line: 148, type: !773, scopeLine: 148, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!773 = !DISubroutineType(types: !774)
!774 = !{null, !591, !34, !34}
!775 = !DISubprogram(name: "append_uninitialized", linkageName: "_ZN6String20append_uninitializedEi", scope: !554, file: !555, line: 149, type: !776, scopeLine: 149, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!776 = !DISubroutineType(types: !777)
!777 = !{!778, !591, !34}
!778 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !93, size: 64)
!779 = !DISubprogram(name: "append_garbage", linkageName: "_ZN6String14append_garbageEi", scope: !554, file: !555, line: 150, type: !776, scopeLine: 150, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!780 = !DISubprogram(name: "operator+=", linkageName: "_ZN6StringpLERKS_", scope: !554, file: !555, line: 152, type: !755, scopeLine: 152, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!781 = !DISubprogram(name: "operator+=", linkageName: "_ZN6StringpLEPKc", scope: !554, file: !555, line: 153, type: !762, scopeLine: 153, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!782 = !DISubprogram(name: "operator+=", linkageName: "_ZN6StringpLEc", scope: !554, file: !555, line: 154, type: !783, scopeLine: 154, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!783 = !DISubroutineType(types: !784)
!784 = !{!757, !591, !93}
!785 = !DISubprogram(name: "is_shared", linkageName: "_ZNK6String9is_sharedEv", scope: !554, file: !555, line: 160, type: !687, scopeLine: 160, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!786 = !DISubprogram(name: "is_stable", linkageName: "_ZNK6String9is_stableEv", scope: !554, file: !555, line: 161, type: !687, scopeLine: 161, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!787 = !DISubprogram(name: "unique", linkageName: "_ZNK6String6uniqueEv", scope: !554, file: !555, line: 163, type: !722, scopeLine: 163, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!788 = !DISubprogram(name: "unshared", linkageName: "_ZNK6String8unsharedEv", scope: !554, file: !555, line: 164, type: !722, scopeLine: 164, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!789 = !DISubprogram(name: "compact", linkageName: "_ZNK6String7compactEv", scope: !554, file: !555, line: 165, type: !722, scopeLine: 165, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!790 = !DISubprogram(name: "mutable_data", linkageName: "_ZN6String12mutable_dataEv", scope: !554, file: !555, line: 167, type: !791, scopeLine: 167, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!791 = !DISubroutineType(types: !792)
!792 = !{!778, !591}
!793 = !DISubprogram(name: "mutable_c_str", linkageName: "_ZN6String13mutable_c_strEv", scope: !554, file: !555, line: 168, type: !791, scopeLine: 168, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!794 = !DISubprogram(name: "make_out_of_memory", linkageName: "_ZN6String18make_out_of_memoryEv", scope: !554, file: !555, line: 170, type: !650, scopeLine: 170, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!795 = !DISubprogram(name: "out_of_memory", linkageName: "_ZNK6String13out_of_memoryEv", scope: !554, file: !555, line: 171, type: !687, scopeLine: 171, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!796 = !DISubprogram(name: "out_of_memory_data", linkageName: "_ZN6String18out_of_memory_dataEv", scope: !554, file: !555, line: 172, type: !797, scopeLine: 172, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!797 = !DISubroutineType(types: !798)
!798 = !{!566}
!799 = !DISubprogram(name: "out_of_memory_length", linkageName: "_ZN6String20out_of_memory_lengthEv", scope: !554, file: !555, line: 173, type: !800, scopeLine: 173, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!800 = !DISubroutineType(types: !801)
!801 = !{!34}
!802 = !DISubprogram(name: "empty_data", linkageName: "_ZN6String10empty_dataEv", scope: !554, file: !555, line: 174, type: !797, scopeLine: 174, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!803 = !DISubprogram(name: "skip_utf8_char", linkageName: "_ZN6String14skip_utf8_charEPKcS1_", scope: !554, file: !555, line: 180, type: !804, scopeLine: 180, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!804 = !DISubroutineType(types: !805)
!805 = !{!566, !566, !566}
!806 = !DISubprogram(name: "skip_utf8_char", linkageName: "_ZN6String14skip_utf8_charEPKhS1_", scope: !554, file: !555, line: 181, type: !807, scopeLine: 181, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!807 = !DISubroutineType(types: !808)
!808 = !{!255, !255, !255}
!809 = !DISubprogram(name: "assign_memo", linkageName: "_ZNK6String11assign_memoEPKciPNS_6memo_tE", scope: !554, file: !555, line: 256, type: !810, scopeLine: 256, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!810 = !DISubroutineType(types: !811)
!811 = !{null, !676, !566, !34, !569}
!812 = !DISubprogram(name: "String", scope: !554, file: !555, line: 263, type: !813, scopeLine: 263, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!813 = !DISubroutineType(types: !814)
!814 = !{null, !591, !566, !34, !569}
!815 = !DISubprogram(name: "assign", linkageName: "_ZNK6String6assignERKS_", scope: !554, file: !555, line: 267, type: !816, scopeLine: 267, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!816 = !DISubroutineType(types: !817)
!817 = !{null, !676, !595}
!818 = !DISubprogram(name: "deref", linkageName: "_ZNK6String5derefEv", scope: !554, file: !555, line: 271, type: !819, scopeLine: 271, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!819 = !DISubroutineType(types: !820)
!820 = !{null, !676}
!821 = !DISubprogram(name: "assign", linkageName: "_ZN6String6assignEPKcib", scope: !554, file: !555, line: 280, type: !822, scopeLine: 280, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!822 = !DISubroutineType(types: !823)
!823 = !{null, !591, !566, !34, !53}
!824 = !DISubprogram(name: "assign_out_of_memory", linkageName: "_ZN6String20assign_out_of_memoryEv", scope: !554, file: !555, line: 281, type: !589, scopeLine: 281, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!825 = !DISubprogram(name: "append", linkageName: "_ZN6String6appendEPKciPNS_6memo_tE", scope: !554, file: !555, line: 282, type: !813, scopeLine: 282, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!826 = !DISubprogram(name: "hard_make_stable", linkageName: "_ZN6String16hard_make_stableEPKci", scope: !554, file: !555, line: 283, type: !660, scopeLine: 283, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!827 = !DISubprogram(name: "absent_memo", linkageName: "_ZN6String11absent_memoEv", scope: !554, file: !555, line: 284, type: !828, scopeLine: 284, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!828 = !DISubroutineType(types: !829)
!829 = !{!569}
!830 = !DISubprogram(name: "create_memo", linkageName: "_ZN6String11create_memoEPcii", scope: !554, file: !555, line: 287, type: !831, scopeLine: 287, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!831 = !DISubroutineType(types: !832)
!832 = !{!569, !778, !34, !34}
!833 = !DISubprogram(name: "delete_memo", linkageName: "_ZN6String11delete_memoEPNS_6memo_tE", scope: !554, file: !555, line: 288, type: !834, scopeLine: 288, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!834 = !DISubroutineType(types: !835)
!835 = !{null, !569}
!836 = !DISubprogram(name: "hard_c_str", linkageName: "_ZNK6String10hard_c_strEv", scope: !554, file: !555, line: 289, type: !674, scopeLine: 289, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!837 = !DISubprogram(name: "hard_equals", linkageName: "_ZNK6String11hard_equalsEPKci", scope: !554, file: !555, line: 290, type: !728, scopeLine: 290, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!838 = !DISubprogram(name: "make_claim", linkageName: "_ZN6String10make_claimEPcii", scope: !554, file: !555, line: 299, type: !839, scopeLine: 299, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!839 = !DISubroutineType(types: !840)
!840 = !{!554, !778, !34, !34}
!841 = !DISubprogram(name: "unparse_interval", linkageName: "_ZNK9Timestamp16unparse_intervalEv", scope: !386, file: !387, line: 501, type: !552, scopeLine: 501, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!842 = !DISubprogram(name: "msec_to_subsec", linkageName: "_ZN9Timestamp14msec_to_subsecEj", scope: !386, file: !387, line: 510, type: !843, scopeLine: 510, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!843 = !DISubroutineType(types: !844)
!844 = !{!12, !12}
!845 = !DISubprogram(name: "usec_to_subsec", linkageName: "_ZN9Timestamp14usec_to_subsecEj", scope: !386, file: !387, line: 514, type: !843, scopeLine: 514, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!846 = !DISubprogram(name: "nsec_to_subsec", linkageName: "_ZN9Timestamp14nsec_to_subsecEj", scope: !386, file: !387, line: 518, type: !843, scopeLine: 518, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!847 = !DISubprogram(name: "subsec_to_msec", linkageName: "_ZN9Timestamp14subsec_to_msecEj", scope: !386, file: !387, line: 522, type: !843, scopeLine: 522, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!848 = !DISubprogram(name: "subsec_to_usec", linkageName: "_ZN9Timestamp14subsec_to_usecEj", scope: !386, file: !387, line: 526, type: !843, scopeLine: 526, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!849 = !DISubprogram(name: "subsec_to_nsec", linkageName: "_ZN9Timestamp14subsec_to_nsecEj", scope: !386, file: !387, line: 530, type: !843, scopeLine: 530, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!850 = !DISubprogram(name: "warp_class", linkageName: "_ZN9Timestamp10warp_classEv", scope: !386, file: !387, line: 581, type: !800, scopeLine: 581, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!851 = !DISubprogram(name: "warp_speed", linkageName: "_ZN9Timestamp10warp_speedEv", scope: !386, file: !387, line: 588, type: !852, scopeLine: 588, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!852 = !DISubroutineType(types: !853)
!853 = !{!415}
!854 = !DISubprogram(name: "warp_set_class", linkageName: "_ZN9Timestamp14warp_set_classENS_15warp_class_typeEd", scope: !386, file: !387, line: 621, type: !855, scopeLine: 621, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!855 = !DISubroutineType(types: !856)
!856 = !{null, !857, !415}
!857 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "warp_class_type", scope: !386, file: !387, line: 571, baseType: !16, size: 32, elements: !858, identifier: "_ZTSN9Timestamp15warp_class_typeE")
!858 = !{!859, !860, !861, !862}
!859 = !DIEnumerator(name: "warp_none", value: 0, isUnsigned: true)
!860 = !DIEnumerator(name: "warp_linear", value: 1, isUnsigned: true)
!861 = !DIEnumerator(name: "warp_nowait", value: 2, isUnsigned: true)
!862 = !DIEnumerator(name: "warp_simulation", value: 3, isUnsigned: true)
!863 = !DISubprogram(name: "warp_set_now", linkageName: "_ZN9Timestamp12warp_set_nowERKS_S1_", scope: !386, file: !387, line: 628, type: !864, scopeLine: 628, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!864 = !DISubroutineType(types: !865)
!865 = !{null, !384, !384}
!866 = !DISubprogram(name: "warp_real_delay", linkageName: "_ZNK9Timestamp15warp_real_delayEv", scope: !386, file: !387, line: 632, type: !498, scopeLine: 632, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!867 = !DISubprogram(name: "warp_jumping", linkageName: "_ZN9Timestamp12warp_jumpingEv", scope: !386, file: !387, line: 635, type: !868, scopeLine: 635, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!868 = !DISubroutineType(types: !869)
!869 = !{!53}
!870 = !DISubprogram(name: "warp_jump_steady", linkageName: "_ZN9Timestamp16warp_jump_steadyERKS_", scope: !386, file: !387, line: 640, type: !871, scopeLine: 640, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!871 = !DISubroutineType(types: !872)
!872 = !{null, !384}
!873 = !DISubprogram(name: "now_unwarped", linkageName: "_ZN9Timestamp12now_unwarpedEv", scope: !386, file: !387, line: 647, type: !528, scopeLine: 647, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!874 = !DISubprogram(name: "assign_now_unwarped", linkageName: "_ZN9Timestamp19assign_now_unwarpedEv", scope: !386, file: !387, line: 653, type: !397, scopeLine: 653, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!875 = !DISubprogram(name: "now_steady_unwarped", linkageName: "_ZN9Timestamp19now_steady_unwarpedEv", scope: !386, file: !387, line: 659, type: !528, scopeLine: 659, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!876 = !DISubprogram(name: "assign_now_steady_unwarped", linkageName: "_ZN9Timestamp26assign_now_steady_unwarpedEv", scope: !386, file: !387, line: 666, type: !397, scopeLine: 666, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!877 = !DISubprogram(name: "add_fix", linkageName: "_ZN9Timestamp7add_fixEv", scope: !386, file: !387, line: 674, type: !397, scopeLine: 674, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!878 = !DISubprogram(name: "sub_fix", linkageName: "_ZN9Timestamp7sub_fixEv", scope: !386, file: !387, line: 686, type: !397, scopeLine: 686, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!879 = !DISubprogram(name: "value_div", linkageName: "_ZN9Timestamp9value_divElj", scope: !386, file: !387, line: 698, type: !880, scopeLine: 698, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!880 = !DISubroutineType(types: !881)
!881 = !{!494, !494, !12}
!882 = !DISubprogram(name: "value_div_mod", linkageName: "_ZN9Timestamp13value_div_modERiS0_lj", scope: !386, file: !387, line: 702, type: !883, scopeLine: 702, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!883 = !DISubroutineType(types: !884)
!884 = !{null, !885, !885, !494, !12}
!885 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !31, size: 64)
!886 = !DISubprogram(name: "assign_now", linkageName: "_ZN9Timestamp10assign_nowEbbb", scope: !386, file: !387, line: 709, type: !887, scopeLine: 709, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!887 = !DISubroutineType(types: !888)
!888 = !{null, !399, !53, !53, !53}
!889 = !DISubprogram(name: "warp_adjust", linkageName: "_ZN9Timestamp11warp_adjustEbRKS_S1_", scope: !386, file: !387, line: 712, type: !890, scopeLine: 712, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!890 = !DISubroutineType(types: !891)
!891 = !{null, !53, !384, !384}
!892 = !DISubprogram(name: "warped", linkageName: "_ZNK9Timestamp6warpedEb", scope: !386, file: !387, line: 713, type: !893, scopeLine: 713, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!893 = !DISubroutineType(types: !894)
!894 = !{!386, !461, !53}
!895 = !DISubprogram(name: "warp", linkageName: "_ZN9Timestamp4warpEbb", scope: !386, file: !387, line: 714, type: !896, scopeLine: 714, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!896 = !DISubroutineType(types: !897)
!897 = !{null, !399, !53, !53}
!898 = !DISubprogram(name: "timestamp_anno", linkageName: "_ZN6Packet14timestamp_annoEv", scope: !5, file: !4, line: 356, type: !899, scopeLine: 356, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!899 = !DISubroutineType(types: !900)
!900 = !{!901, !241}
!901 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !386, size: 64)
!902 = !DISubprogram(name: "set_timestamp_anno", linkageName: "_ZN6Packet18set_timestamp_annoERK9Timestamp", scope: !5, file: !4, line: 359, type: !903, scopeLine: 359, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!903 = !DISubroutineType(types: !904)
!904 = !{null, !241, !384}
!905 = !DISubprogram(name: "device_anno", linkageName: "_ZNK6Packet11device_annoEv", scope: !5, file: !4, line: 362, type: !906, scopeLine: 362, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!906 = !DISubroutineType(types: !907)
!907 = !{!908, !245}
!908 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !909, size: 64)
!909 = !DIDerivedType(tag: DW_TAG_typedef, name: "net_device", file: !506, line: 326, baseType: !910)
!910 = !DICompositeType(tag: DW_TAG_structure_type, name: "device", file: !506, line: 326, flags: DIFlagFwdDecl, identifier: "_ZTS6device")
!911 = !DISubprogram(name: "set_device_anno", linkageName: "_ZN6Packet15set_device_annoEP6device", scope: !5, file: !4, line: 364, type: !912, scopeLine: 364, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!912 = !DISubroutineType(types: !913)
!913 = !{null, !241, !908}
!914 = !DISubprogram(name: "packet_type_anno", linkageName: "_ZNK6Packet16packet_type_annoEv", scope: !5, file: !4, line: 383, type: !915, scopeLine: 383, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!915 = !DISubroutineType(types: !916)
!916 = !{!3, !245}
!917 = !DISubprogram(name: "set_packet_type_anno", linkageName: "_ZN6Packet20set_packet_type_annoENS_10PacketTypeE", scope: !5, file: !4, line: 385, type: !918, scopeLine: 385, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!918 = !DISubroutineType(types: !919)
!919 = !{null, !241, !3}
!920 = !DISubprogram(name: "next", linkageName: "_ZNK6Packet4nextEv", scope: !5, file: !4, line: 410, type: !921, scopeLine: 410, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!921 = !DISubroutineType(types: !922)
!922 = !{!78, !245}
!923 = !DISubprogram(name: "next", linkageName: "_ZN6Packet4nextEv", scope: !5, file: !4, line: 412, type: !924, scopeLine: 412, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!924 = !DISubroutineType(types: !925)
!925 = !{!926, !241}
!926 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !78, size: 64)
!927 = !DISubprogram(name: "set_next", linkageName: "_ZN6Packet8set_nextEPS_", scope: !5, file: !4, line: 414, type: !928, scopeLine: 414, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!928 = !DISubroutineType(types: !929)
!929 = !{null, !241, !78}
!930 = !DISubprogram(name: "prev", linkageName: "_ZNK6Packet4prevEv", scope: !5, file: !4, line: 417, type: !921, scopeLine: 417, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!931 = !DISubprogram(name: "prev", linkageName: "_ZN6Packet4prevEv", scope: !5, file: !4, line: 419, type: !924, scopeLine: 419, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!932 = !DISubprogram(name: "set_prev", linkageName: "_ZN6Packet8set_prevEPS_", scope: !5, file: !4, line: 421, type: !928, scopeLine: 421, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!933 = !DISubprogram(name: "dst_ip_anno", linkageName: "_ZNK6Packet11dst_ip_annoEv", scope: !5, file: !4, line: 431, type: !934, scopeLine: 431, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!934 = !DISubroutineType(types: !935)
!935 = !{!936, !245}
!936 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "IPAddress", file: !937, line: 15, size: 32, flags: DIFlagTypePassByValue | DIFlagNonTrivial, elements: !938, identifier: "_ZTS9IPAddress")
!937 = !DIFile(filename: "../dummy_inc/click/ipaddress.hh", directory: "/home/john/projects/click/ir-dir")
!938 = !{!939, !940, !944, !947, !950, !953, !956, !959, !962, !965, !970, !973, !976, !981, !984, !985, !986, !987, !990, !991, !994, !997, !998, !1001, !1004, !1007, !1008, !1012, !1013, !1014, !1017, !1018, !1021, !1022}
!939 = !DIDerivedType(tag: DW_TAG_member, name: "_addr", scope: !936, file: !937, line: 152, baseType: !12, size: 32)
!940 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 20, type: !941, scopeLine: 20, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!941 = !DISubroutineType(types: !942)
!942 = !{null, !943}
!943 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !936, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!944 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 25, type: !945, scopeLine: 25, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!945 = !DISubroutineType(types: !946)
!946 = !{null, !943, !16}
!947 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 29, type: !948, scopeLine: 29, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!948 = !DISubroutineType(types: !949)
!949 = !{null, !943, !34}
!950 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 33, type: !951, scopeLine: 33, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!951 = !DISubroutineType(types: !952)
!952 = !{null, !943, !115}
!953 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 37, type: !954, scopeLine: 37, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!954 = !DISubroutineType(types: !955)
!955 = !{null, !943, !395}
!956 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 42, type: !957, scopeLine: 42, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!957 = !DISubroutineType(types: !958)
!958 = !{null, !943, !176}
!959 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 50, type: !960, scopeLine: 50, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!960 = !DISubroutineType(types: !961)
!961 = !{null, !943, !255}
!962 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 63, type: !963, scopeLine: 63, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!963 = !DISubroutineType(types: !964)
!964 = !{null, !943, !595}
!965 = !DISubprogram(name: "IPAddress", scope: !936, file: !937, line: 66, type: !966, scopeLine: 66, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!966 = !DISubroutineType(types: !967)
!967 = !{null, !943, !968}
!968 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !969, size: 64)
!969 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !450)
!970 = !DISubprogram(name: "make_prefix", linkageName: "_ZN9IPAddress11make_prefixEi", scope: !936, file: !937, line: 78, type: !971, scopeLine: 78, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!971 = !DISubroutineType(types: !972)
!972 = !{!936, !34}
!973 = !DISubprogram(name: "make_broadcast", linkageName: "_ZN9IPAddress14make_broadcastEv", scope: !936, file: !937, line: 81, type: !974, scopeLine: 81, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!974 = !DISubroutineType(types: !975)
!975 = !{!936}
!976 = !DISubprogram(name: "empty", linkageName: "_ZNK9IPAddress5emptyEv", scope: !936, file: !937, line: 86, type: !977, scopeLine: 86, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!977 = !DISubroutineType(types: !978)
!978 = !{!53, !979}
!979 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !980, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!980 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !936)
!981 = !DISubprogram(name: "addr", linkageName: "_ZNK9IPAddress4addrEv", scope: !936, file: !937, line: 91, type: !982, scopeLine: 91, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!982 = !DISubroutineType(types: !983)
!983 = !{!12, !979}
!984 = !DISubprogram(name: "operator unsigned int", linkageName: "_ZNK9IPAddresscvjEv", scope: !936, file: !937, line: 99, type: !982, scopeLine: 99, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!985 = !DISubprogram(name: "is_multicast", linkageName: "_ZNK9IPAddress12is_multicastEv", scope: !936, file: !937, line: 106, type: !977, scopeLine: 106, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!986 = !DISubprogram(name: "is_link_local", linkageName: "_ZNK9IPAddress13is_link_localEv", scope: !936, file: !937, line: 110, type: !977, scopeLine: 110, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!987 = !DISubprogram(name: "in_addr", linkageName: "_ZNK9IPAddress7in_addrEv", scope: !936, file: !937, line: 114, type: !988, scopeLine: 114, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!988 = !DISubroutineType(types: !989)
!989 = !{!176, !979}
!990 = !DISubprogram(name: "operator in_addr", linkageName: "_ZNK9IPAddresscv7in_addrEv", scope: !936, file: !937, line: 115, type: !988, scopeLine: 115, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!991 = !DISubprogram(name: "data", linkageName: "_ZN9IPAddress4dataEv", scope: !936, file: !937, line: 117, type: !992, scopeLine: 117, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!992 = !DISubroutineType(types: !993)
!993 = !{!80, !943}
!994 = !DISubprogram(name: "data", linkageName: "_ZNK9IPAddress4dataEv", scope: !936, file: !937, line: 118, type: !995, scopeLine: 118, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!995 = !DISubroutineType(types: !996)
!996 = !{!255, !979}
!997 = !DISubprogram(name: "hashcode", linkageName: "_ZNK9IPAddress8hashcodeEv", scope: !936, file: !937, line: 120, type: !982, scopeLine: 120, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!998 = !DISubprogram(name: "mask_to_prefix_len", linkageName: "_ZNK9IPAddress18mask_to_prefix_lenEv", scope: !936, file: !937, line: 122, type: !999, scopeLine: 122, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!999 = !DISubroutineType(types: !1000)
!1000 = !{!34, !979}
!1001 = !DISubprogram(name: "matches_prefix", linkageName: "_ZNK9IPAddress14matches_prefixES_S_", scope: !936, file: !937, line: 123, type: !1002, scopeLine: 123, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1002 = !DISubroutineType(types: !1003)
!1003 = !{!53, !979, !936, !936}
!1004 = !DISubprogram(name: "mask_as_specific", linkageName: "_ZNK9IPAddress16mask_as_specificES_", scope: !936, file: !937, line: 124, type: !1005, scopeLine: 124, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1005 = !DISubroutineType(types: !1006)
!1006 = !{!53, !979, !936}
!1007 = !DISubprogram(name: "mask_more_specific", linkageName: "_ZNK9IPAddress18mask_more_specificES_", scope: !936, file: !937, line: 125, type: !1005, scopeLine: 125, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1008 = !DISubprogram(name: "operator&=", linkageName: "_ZN9IPAddressaNES_", scope: !936, file: !937, line: 137, type: !1009, scopeLine: 137, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1009 = !DISubroutineType(types: !1010)
!1010 = !{!1011, !943, !936}
!1011 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !936, size: 64)
!1012 = !DISubprogram(name: "operator|=", linkageName: "_ZN9IPAddressoRES_", scope: !936, file: !937, line: 138, type: !1009, scopeLine: 138, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1013 = !DISubprogram(name: "operator^=", linkageName: "_ZN9IPAddresseOES_", scope: !936, file: !937, line: 139, type: !1009, scopeLine: 139, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1014 = !DISubprogram(name: "unparse", linkageName: "_ZNK9IPAddress7unparseEv", scope: !936, file: !937, line: 141, type: !1015, scopeLine: 141, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1015 = !DISubroutineType(types: !1016)
!1016 = !{!554, !979}
!1017 = !DISubprogram(name: "unparse_mask", linkageName: "_ZNK9IPAddress12unparse_maskEv", scope: !936, file: !937, line: 142, type: !1015, scopeLine: 142, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1018 = !DISubprogram(name: "unparse_with_mask", linkageName: "_ZNK9IPAddress17unparse_with_maskES_", scope: !936, file: !937, line: 143, type: !1019, scopeLine: 143, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1019 = !DISubroutineType(types: !1020)
!1020 = !{!554, !979, !936}
!1021 = !DISubprogram(name: "s", linkageName: "_ZNK9IPAddress1sEv", scope: !936, file: !937, line: 145, type: !1015, scopeLine: 145, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1022 = !DISubprogram(name: "operator String", linkageName: "_ZNK9IPAddresscv6StringEv", scope: !936, file: !937, line: 146, type: !1015, scopeLine: 146, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1023 = !DISubprogram(name: "set_dst_ip_anno", linkageName: "_ZN6Packet15set_dst_ip_annoE9IPAddress", scope: !5, file: !4, line: 436, type: !1024, scopeLine: 436, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1024 = !DISubroutineType(types: !1025)
!1025 = !{null, !241, !936}
!1026 = !DISubprogram(name: "anno", linkageName: "_ZN6Packet4annoEv", scope: !5, file: !4, line: 441, type: !273, scopeLine: 441, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1027 = !DISubprogram(name: "anno", linkageName: "_ZNK6Packet4annoEv", scope: !5, file: !4, line: 444, type: !1028, scopeLine: 444, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1028 = !DISubroutineType(types: !1029)
!1029 = !{!224, !245}
!1030 = !DISubprogram(name: "anno_u8", linkageName: "_ZN6Packet7anno_u8Ev", scope: !5, file: !4, line: 447, type: !1031, scopeLine: 447, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1031 = !DISubroutineType(types: !1032)
!1032 = !{!1033, !241}
!1033 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !98, size: 64)
!1034 = !DISubprogram(name: "anno_u8", linkageName: "_ZNK6Packet7anno_u8Ev", scope: !5, file: !4, line: 450, type: !1035, scopeLine: 450, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1035 = !DISubroutineType(types: !1036)
!1036 = !{!1037, !245}
!1037 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1038, size: 64)
!1038 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !98)
!1039 = !DISubprogram(name: "anno_u32", linkageName: "_ZN6Packet8anno_u32Ev", scope: !5, file: !4, line: 453, type: !1040, scopeLine: 453, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1040 = !DISubroutineType(types: !1041)
!1041 = !{!1042, !241}
!1042 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 64)
!1043 = !DISubprogram(name: "anno_u32", linkageName: "_ZNK6Packet8anno_u32Ev", scope: !5, file: !4, line: 456, type: !1044, scopeLine: 456, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1044 = !DISubroutineType(types: !1045)
!1045 = !{!1046, !245}
!1046 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1047, size: 64)
!1047 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !12)
!1048 = !DISubprogram(name: "anno_u8", linkageName: "_ZNK6Packet7anno_u8Ei", scope: !5, file: !4, line: 460, type: !1049, scopeLine: 460, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1049 = !DISubroutineType(types: !1050)
!1050 = !{!98, !245, !34}
!1051 = !DISubprogram(name: "set_anno_u8", linkageName: "_ZN6Packet11set_anno_u8Eih", scope: !5, file: !4, line: 469, type: !1052, scopeLine: 469, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1052 = !DISubroutineType(types: !1053)
!1053 = !{null, !241, !34, !98}
!1054 = !DISubprogram(name: "anno_u16", linkageName: "_ZNK6Packet8anno_u16Ei", scope: !5, file: !4, line: 479, type: !1055, scopeLine: 479, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1055 = !DISubroutineType(types: !1056)
!1056 = !{!102, !245, !34}
!1057 = !DISubprogram(name: "set_anno_u16", linkageName: "_ZN6Packet12set_anno_u16Eit", scope: !5, file: !4, line: 494, type: !1058, scopeLine: 494, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1058 = !DISubroutineType(types: !1059)
!1059 = !{null, !241, !34, !102}
!1060 = !DISubprogram(name: "anno_s16", linkageName: "_ZNK6Packet8anno_s16Ei", scope: !5, file: !4, line: 507, type: !1061, scopeLine: 507, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1061 = !DISubroutineType(types: !1062)
!1062 = !{!1063, !245, !34}
!1063 = !DIDerivedType(tag: DW_TAG_typedef, name: "int16_t", file: !32, line: 25, baseType: !1064)
!1064 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int16_t", file: !15, line: 39, baseType: !1065)
!1065 = !DIBasicType(name: "short", size: 16, encoding: DW_ATE_signed)
!1066 = !DISubprogram(name: "set_anno_s16", linkageName: "_ZN6Packet12set_anno_s16Eis", scope: !5, file: !4, line: 522, type: !1067, scopeLine: 522, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1067 = !DISubroutineType(types: !1068)
!1068 = !{null, !241, !34, !1063}
!1069 = !DISubprogram(name: "anno_u32", linkageName: "_ZNK6Packet8anno_u32Ei", scope: !5, file: !4, line: 535, type: !1070, scopeLine: 535, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1070 = !DISubroutineType(types: !1071)
!1071 = !{!12, !245, !34}
!1072 = !DISubprogram(name: "set_anno_u32", linkageName: "_ZN6Packet12set_anno_u32Eij", scope: !5, file: !4, line: 550, type: !1073, scopeLine: 550, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1073 = !DISubroutineType(types: !1074)
!1074 = !{null, !241, !34, !12}
!1075 = !DISubprogram(name: "anno_s32", linkageName: "_ZNK6Packet8anno_s32Ei", scope: !5, file: !4, line: 556, type: !1076, scopeLine: 556, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1076 = !DISubroutineType(types: !1077)
!1077 = !{!31, !245, !34}
!1078 = !DISubprogram(name: "set_anno_s32", linkageName: "_ZN6Packet12set_anno_s32Eii", scope: !5, file: !4, line: 571, type: !1079, scopeLine: 571, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1079 = !DISubroutineType(types: !1080)
!1080 = !{null, !241, !34, !31}
!1081 = !DISubprogram(name: "anno_u64", linkageName: "_ZNK6Packet8anno_u64Ei", scope: !5, file: !4, line: 585, type: !1082, scopeLine: 585, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1082 = !DISubroutineType(types: !1083)
!1083 = !{!113, !245, !34}
!1084 = !DISubprogram(name: "set_anno_u64", linkageName: "_ZN6Packet12set_anno_u64Eim", scope: !5, file: !4, line: 600, type: !1085, scopeLine: 600, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1085 = !DISubroutineType(types: !1086)
!1086 = !{null, !241, !34, !113}
!1087 = !DISubprogram(name: "anno_ptr", linkageName: "_ZNK6Packet8anno_ptrEi", scope: !5, file: !4, line: 614, type: !1088, scopeLine: 614, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1088 = !DISubroutineType(types: !1089)
!1089 = !{!135, !245, !34}
!1090 = !DISubprogram(name: "set_anno_ptr", linkageName: "_ZN6Packet12set_anno_ptrEiPKv", scope: !5, file: !4, line: 629, type: !1091, scopeLine: 629, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1091 = !DISubroutineType(types: !1092)
!1092 = !{null, !241, !34, !224}
!1093 = !DISubprogram(name: "data_packet", linkageName: "_ZN6Packet11data_packetEv", scope: !5, file: !4, line: 638, type: !247, scopeLine: 638, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1094 = !DISubprogram(name: "clear_annotations", linkageName: "_ZN6Packet17clear_annotationsEb", scope: !5, file: !4, line: 643, type: !1095, scopeLine: 643, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1095 = !DISubroutineType(types: !1096)
!1096 = !{null, !241, !53}
!1097 = !DISubprogram(name: "copy_annotations", linkageName: "_ZN6Packet16copy_annotationsEPKS_", scope: !5, file: !4, line: 644, type: !1098, scopeLine: 644, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1098 = !DISubroutineType(types: !1099)
!1099 = !{null, !241, !1100}
!1100 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !213, size: 64)
!1101 = !DISubprogram(name: "buffer_data", linkageName: "_ZNK6Packet11buffer_dataEv", scope: !5, file: !4, line: 661, type: !253, scopeLine: 661, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1102 = !DISubprogram(name: "addr_anno", linkageName: "_ZN6Packet9addr_annoEv", scope: !5, file: !4, line: 662, type: !273, scopeLine: 662, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1103 = !DISubprogram(name: "addr_anno", linkageName: "_ZNK6Packet9addr_annoEv", scope: !5, file: !4, line: 663, type: !1028, scopeLine: 663, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1104 = !DISubprogram(name: "user_anno", linkageName: "_ZN6Packet9user_annoEv", scope: !5, file: !4, line: 664, type: !273, scopeLine: 664, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1105 = !DISubprogram(name: "user_anno", linkageName: "_ZNK6Packet9user_annoEv", scope: !5, file: !4, line: 665, type: !1028, scopeLine: 665, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1106 = !DISubprogram(name: "user_anno_u8", linkageName: "_ZN6Packet12user_anno_u8Ev", scope: !5, file: !4, line: 666, type: !1031, scopeLine: 666, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1107 = !DISubprogram(name: "user_anno_u8", linkageName: "_ZNK6Packet12user_anno_u8Ev", scope: !5, file: !4, line: 667, type: !1035, scopeLine: 667, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1108 = !DISubprogram(name: "user_anno_u32", linkageName: "_ZN6Packet13user_anno_u32Ev", scope: !5, file: !4, line: 668, type: !1040, scopeLine: 668, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1109 = !DISubprogram(name: "user_anno_u32", linkageName: "_ZNK6Packet13user_anno_u32Ev", scope: !5, file: !4, line: 669, type: !1044, scopeLine: 669, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1110 = !DISubprogram(name: "user_anno_u8", linkageName: "_ZNK6Packet12user_anno_u8Ei", scope: !5, file: !4, line: 670, type: !1049, scopeLine: 670, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1111 = !DISubprogram(name: "set_user_anno_u8", linkageName: "_ZN6Packet16set_user_anno_u8Eih", scope: !5, file: !4, line: 671, type: !1052, scopeLine: 671, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1112 = !DISubprogram(name: "user_anno_u16", linkageName: "_ZNK6Packet13user_anno_u16Ei", scope: !5, file: !4, line: 672, type: !1055, scopeLine: 672, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1113 = !DISubprogram(name: "set_user_anno_u16", linkageName: "_ZN6Packet17set_user_anno_u16Eit", scope: !5, file: !4, line: 673, type: !1058, scopeLine: 673, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1114 = !DISubprogram(name: "user_anno_u32", linkageName: "_ZNK6Packet13user_anno_u32Ei", scope: !5, file: !4, line: 674, type: !1070, scopeLine: 674, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1115 = !DISubprogram(name: "set_user_anno_u32", linkageName: "_ZN6Packet17set_user_anno_u32Eij", scope: !5, file: !4, line: 675, type: !1073, scopeLine: 675, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1116 = !DISubprogram(name: "user_anno_s32", linkageName: "_ZNK6Packet13user_anno_s32Ei", scope: !5, file: !4, line: 676, type: !1076, scopeLine: 676, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1117 = !DISubprogram(name: "set_user_anno_s32", linkageName: "_ZN6Packet17set_user_anno_s32Eii", scope: !5, file: !4, line: 677, type: !1079, scopeLine: 677, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1118 = !DISubprogram(name: "user_anno_u64", linkageName: "_ZNK6Packet13user_anno_u64Ei", scope: !5, file: !4, line: 679, type: !1082, scopeLine: 679, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1119 = !DISubprogram(name: "set_user_anno_u64", linkageName: "_ZN6Packet17set_user_anno_u64Eim", scope: !5, file: !4, line: 680, type: !1085, scopeLine: 680, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1120 = !DISubprogram(name: "all_user_anno", linkageName: "_ZNK6Packet13all_user_annoEv", scope: !5, file: !4, line: 682, type: !1035, scopeLine: 682, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1121 = !DISubprogram(name: "all_user_anno", linkageName: "_ZN6Packet13all_user_annoEv", scope: !5, file: !4, line: 683, type: !1031, scopeLine: 683, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1122 = !DISubprogram(name: "all_user_anno_u", linkageName: "_ZNK6Packet15all_user_anno_uEv", scope: !5, file: !4, line: 684, type: !1044, scopeLine: 684, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1123 = !DISubprogram(name: "all_user_anno_u", linkageName: "_ZN6Packet15all_user_anno_uEv", scope: !5, file: !4, line: 685, type: !1040, scopeLine: 685, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1124 = !DISubprogram(name: "user_anno_c", linkageName: "_ZNK6Packet11user_anno_cEi", scope: !5, file: !4, line: 686, type: !1049, scopeLine: 686, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1125 = !DISubprogram(name: "set_user_anno_c", linkageName: "_ZN6Packet15set_user_anno_cEih", scope: !5, file: !4, line: 687, type: !1052, scopeLine: 687, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1126 = !DISubprogram(name: "user_anno_s", linkageName: "_ZNK6Packet11user_anno_sEi", scope: !5, file: !4, line: 688, type: !1061, scopeLine: 688, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1127 = !DISubprogram(name: "set_user_anno_s", linkageName: "_ZN6Packet15set_user_anno_sEis", scope: !5, file: !4, line: 689, type: !1067, scopeLine: 689, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1128 = !DISubprogram(name: "user_anno_us", linkageName: "_ZNK6Packet12user_anno_usEi", scope: !5, file: !4, line: 690, type: !1055, scopeLine: 690, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1129 = !DISubprogram(name: "set_user_anno_us", linkageName: "_ZN6Packet16set_user_anno_usEit", scope: !5, file: !4, line: 691, type: !1058, scopeLine: 691, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1130 = !DISubprogram(name: "user_anno_i", linkageName: "_ZNK6Packet11user_anno_iEi", scope: !5, file: !4, line: 692, type: !1076, scopeLine: 692, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1131 = !DISubprogram(name: "set_user_anno_i", linkageName: "_ZN6Packet15set_user_anno_iEii", scope: !5, file: !4, line: 693, type: !1079, scopeLine: 693, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1132 = !DISubprogram(name: "user_anno_u", linkageName: "_ZNK6Packet11user_anno_uEi", scope: !5, file: !4, line: 694, type: !1070, scopeLine: 694, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1133 = !DISubprogram(name: "set_user_anno_u", linkageName: "_ZN6Packet15set_user_anno_uEij", scope: !5, file: !4, line: 695, type: !1073, scopeLine: 695, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1134 = !DISubprogram(name: "Packet", scope: !5, file: !4, line: 751, type: !239, scopeLine: 751, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1135 = !DISubprogram(name: "Packet", scope: !5, file: !4, line: 756, type: !1136, scopeLine: 756, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1136 = !DISubroutineType(types: !1137)
!1137 = !{null, !241, !212}
!1138 = !DISubprogram(name: "~Packet", scope: !5, file: !4, line: 757, type: !239, scopeLine: 757, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1139 = !DISubprogram(name: "operator=", linkageName: "_ZN6PacketaSERKS_", scope: !5, file: !4, line: 758, type: !1140, scopeLine: 758, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1140 = !DISubroutineType(types: !1141)
!1141 = !{!1142, !241, !212}
!1142 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !5, size: 64)
!1143 = !DISubprogram(name: "alloc_data", linkageName: "_ZN6Packet10alloc_dataEjjj", scope: !5, file: !4, line: 761, type: !1144, scopeLine: 761, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1144 = !DISubroutineType(types: !1145)
!1145 = !{!53, !241, !12, !12, !12}
!1146 = !DISubprogram(name: "shift_header_annotations", linkageName: "_ZN6Packet24shift_header_annotationsEPKhi", scope: !5, file: !4, line: 768, type: !1147, scopeLine: 768, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1147 = !DISubroutineType(types: !1148)
!1148 = !{null, !241, !255, !31}
!1149 = !DISubprogram(name: "expensive_uniqueify", linkageName: "_ZN6Packet19expensive_uniqueifyEiib", scope: !5, file: !4, line: 769, type: !1150, scopeLine: 769, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1150 = !DISubroutineType(types: !1151)
!1151 = !{!140, !241, !31, !31, !53}
!1152 = !DISubprogram(name: "expensive_push", linkageName: "_ZN6Packet14expensive_pushEj", scope: !5, file: !4, line: 770, type: !277, scopeLine: 770, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1153 = !DISubprogram(name: "expensive_put", linkageName: "_ZN6Packet13expensive_putEj", scope: !5, file: !4, line: 771, type: !277, scopeLine: 771, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1154 = !{!1155, !1156, !1157, !1158, !1159, !1160, !1161}
!1155 = !DIEnumerator(name: "HOST", value: 0, isUnsigned: true)
!1156 = !DIEnumerator(name: "BROADCAST", value: 1, isUnsigned: true)
!1157 = !DIEnumerator(name: "MULTICAST", value: 2, isUnsigned: true)
!1158 = !DIEnumerator(name: "OTHERHOST", value: 3, isUnsigned: true)
!1159 = !DIEnumerator(name: "OUTGOING", value: 4, isUnsigned: true)
!1160 = !DIEnumerator(name: "LOOPBACK", value: 5, isUnsigned: true)
!1161 = !DIEnumerator(name: "FASTROUTE", value: 6, isUnsigned: true)
!1162 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "DeprecatedFlags", scope: !1164, file: !1163, line: 252, baseType: !16, size: 32, elements: !1262, identifier: "_ZTSN7Handler15DeprecatedFlagsE")
!1163 = !DIFile(filename: "../dummy_inc/click/handler.hh", directory: "/home/john/projects/click/ir-dir")
!1164 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Handler", file: !1163, line: 19, size: 576, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1165, identifier: "_ZTS7Handler")
!1165 = !{!1166, !1167, !1188, !1197, !1198, !1199, !1200, !1201, !1202, !1203, !1207, !1210, !1213, !1216, !1217, !1218, !1219, !1222, !1223, !1224, !1225, !1226, !1227, !1228, !1229, !1230, !1233, !1236, !1239, !1242, !1245, !1248, !1251, !1255, !1259}
!1166 = !DIDerivedType(tag: DW_TAG_member, name: "_name", scope: !1164, file: !1163, line: 289, baseType: !554, size: 192)
!1167 = !DIDerivedType(tag: DW_TAG_member, name: "_read_hook", scope: !1164, file: !1163, line: 293, baseType: !1168, size: 64, offset: 192)
!1168 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !1164, file: !1163, line: 290, size: 64, flags: DIFlagTypePassByValue, elements: !1169, identifier: "_ZTSN7HandlerUt1_E")
!1169 = !{!1170, !1183}
!1170 = !DIDerivedType(tag: DW_TAG_member, name: "h", scope: !1168, file: !1163, line: 291, baseType: !1171, size: 64)
!1171 = !DIDerivedType(tag: DW_TAG_typedef, name: "HandlerCallback", file: !1163, line: 13, baseType: !1172)
!1172 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1173, size: 64)
!1173 = !DISubroutineType(types: !1174)
!1174 = !{!34, !34, !757, !1175, !1178, !1180}
!1175 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1176, size: 64)
!1176 = !DICompositeType(tag: DW_TAG_class_type, name: "Element", file: !1177, line: 29, flags: DIFlagFwdDecl, identifier: "_ZTS7Element")
!1177 = !DIFile(filename: "../dummy_inc/click/element.hh", directory: "/home/john/projects/click/ir-dir")
!1178 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1179, size: 64)
!1179 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1164)
!1180 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1181, size: 64)
!1181 = !DICompositeType(tag: DW_TAG_class_type, name: "ErrorHandler", file: !1182, line: 90, flags: DIFlagFwdDecl, identifier: "_ZTS12ErrorHandler")
!1182 = !DIFile(filename: "../dummy_inc/click/error.hh", directory: "/home/john/projects/click/ir-dir")
!1183 = !DIDerivedType(tag: DW_TAG_member, name: "r", scope: !1168, file: !1163, line: 292, baseType: !1184, size: 64)
!1184 = !DIDerivedType(tag: DW_TAG_typedef, name: "ReadHandlerCallback", file: !1163, line: 15, baseType: !1185)
!1185 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1186, size: 64)
!1186 = !DISubroutineType(types: !1187)
!1187 = !{!554, !1175, !135}
!1188 = !DIDerivedType(tag: DW_TAG_member, name: "_write_hook", scope: !1164, file: !1163, line: 297, baseType: !1189, size: 64, offset: 256)
!1189 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !1164, file: !1163, line: 294, size: 64, flags: DIFlagTypePassByValue, elements: !1190, identifier: "_ZTSN7HandlerUt2_E")
!1190 = !{!1191, !1192}
!1191 = !DIDerivedType(tag: DW_TAG_member, name: "h", scope: !1189, file: !1163, line: 295, baseType: !1171, size: 64)
!1192 = !DIDerivedType(tag: DW_TAG_member, name: "w", scope: !1189, file: !1163, line: 296, baseType: !1193, size: 64)
!1193 = !DIDerivedType(tag: DW_TAG_typedef, name: "WriteHandlerCallback", file: !1163, line: 16, baseType: !1194)
!1194 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1195, size: 64)
!1195 = !DISubroutineType(types: !1196)
!1196 = !{!34, !595, !1175, !135, !1180}
!1197 = !DIDerivedType(tag: DW_TAG_member, name: "_read_user_data", scope: !1164, file: !1163, line: 298, baseType: !135, size: 64, offset: 320)
!1198 = !DIDerivedType(tag: DW_TAG_member, name: "_write_user_data", scope: !1164, file: !1163, line: 299, baseType: !135, size: 64, offset: 384)
!1199 = !DIDerivedType(tag: DW_TAG_member, name: "_flags", scope: !1164, file: !1163, line: 300, baseType: !12, size: 32, offset: 448)
!1200 = !DIDerivedType(tag: DW_TAG_member, name: "_use_count", scope: !1164, file: !1163, line: 301, baseType: !34, size: 32, offset: 480)
!1201 = !DIDerivedType(tag: DW_TAG_member, name: "_next_by_name", scope: !1164, file: !1163, line: 302, baseType: !34, size: 32, offset: 512)
!1202 = !DIDerivedType(tag: DW_TAG_member, name: "the_blank_handler", scope: !1164, file: !1163, line: 304, baseType: !1178, flags: DIFlagStaticMember)
!1203 = !DISubprogram(name: "name", linkageName: "_ZNK7Handler4nameEv", scope: !1164, file: !1163, line: 62, type: !1204, scopeLine: 62, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1204 = !DISubroutineType(types: !1205)
!1205 = !{!595, !1206}
!1206 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1179, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1207 = !DISubprogram(name: "flags", linkageName: "_ZNK7Handler5flagsEv", scope: !1164, file: !1163, line: 69, type: !1208, scopeLine: 69, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1208 = !DISubroutineType(types: !1209)
!1209 = !{!12, !1206}
!1210 = !DISubprogram(name: "user_data", linkageName: "_ZNK7Handler9user_dataEi", scope: !1164, file: !1163, line: 75, type: !1211, scopeLine: 75, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1211 = !DISubroutineType(types: !1212)
!1212 = !{!135, !1206, !34}
!1213 = !DISubprogram(name: "read_user_data", linkageName: "_ZNK7Handler14read_user_dataEv", scope: !1164, file: !1163, line: 80, type: !1214, scopeLine: 80, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1214 = !DISubroutineType(types: !1215)
!1215 = !{!135, !1206}
!1216 = !DISubprogram(name: "write_user_data", linkageName: "_ZNK7Handler15write_user_dataEv", scope: !1164, file: !1163, line: 85, type: !1214, scopeLine: 85, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1217 = !DISubprogram(name: "user_data1", linkageName: "_ZNK7Handler10user_data1Ev", scope: !1164, file: !1163, line: 90, type: !1214, scopeLine: 90, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1218 = !DISubprogram(name: "user_data2", linkageName: "_ZNK7Handler10user_data2Ev", scope: !1164, file: !1163, line: 91, type: !1214, scopeLine: 91, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1219 = !DISubprogram(name: "readable", linkageName: "_ZNK7Handler8readableEv", scope: !1164, file: !1163, line: 96, type: !1220, scopeLine: 96, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1220 = !DISubroutineType(types: !1221)
!1221 = !{!53, !1206}
!1222 = !DISubprogram(name: "read_param", linkageName: "_ZNK7Handler10read_paramEv", scope: !1164, file: !1163, line: 102, type: !1220, scopeLine: 102, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1223 = !DISubprogram(name: "read_visible", linkageName: "_ZNK7Handler12read_visibleEv", scope: !1164, file: !1163, line: 111, type: !1220, scopeLine: 111, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1224 = !DISubprogram(name: "writable", linkageName: "_ZNK7Handler8writableEv", scope: !1164, file: !1163, line: 116, type: !1220, scopeLine: 116, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1225 = !DISubprogram(name: "write_visible", linkageName: "_ZNK7Handler13write_visibleEv", scope: !1164, file: !1163, line: 125, type: !1220, scopeLine: 125, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1226 = !DISubprogram(name: "visible", linkageName: "_ZNK7Handler7visibleEv", scope: !1164, file: !1163, line: 130, type: !1220, scopeLine: 130, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1227 = !DISubprogram(name: "allow_concurrent_handlers", linkageName: "_ZNK7Handler25allow_concurrent_handlersEv", scope: !1164, file: !1163, line: 136, type: !1220, scopeLine: 136, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1228 = !DISubprogram(name: "allow_concurrent_threads", linkageName: "_ZNK7Handler24allow_concurrent_threadsEv", scope: !1164, file: !1163, line: 142, type: !1220, scopeLine: 142, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1229 = !DISubprogram(name: "raw", linkageName: "_ZNK7Handler3rawEv", scope: !1164, file: !1163, line: 164, type: !1220, scopeLine: 164, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1230 = !DISubprogram(name: "call_read", linkageName: "_ZNK7Handler9call_readEP7ElementRK6StringP12ErrorHandler", scope: !1164, file: !1163, line: 177, type: !1231, scopeLine: 177, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1231 = !DISubroutineType(types: !1232)
!1232 = !{!554, !1206, !1175, !595, !1180}
!1233 = !DISubprogram(name: "call_read", linkageName: "_ZNK7Handler9call_readEP7ElementP12ErrorHandler", scope: !1164, file: !1163, line: 186, type: !1234, scopeLine: 186, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1234 = !DISubroutineType(types: !1235)
!1235 = !{!554, !1206, !1175, !1180}
!1236 = !DISubprogram(name: "call_write", linkageName: "_ZNK7Handler10call_writeERK6StringP7ElementP12ErrorHandler", scope: !1164, file: !1163, line: 198, type: !1237, scopeLine: 198, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1237 = !DISubroutineType(types: !1238)
!1238 = !{!34, !1206, !595, !1175, !1180}
!1239 = !DISubprogram(name: "unparse_name", linkageName: "_ZNK7Handler12unparse_nameEP7Element", scope: !1164, file: !1163, line: 207, type: !1240, scopeLine: 207, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1240 = !DISubroutineType(types: !1241)
!1241 = !{!554, !1206, !1175}
!1242 = !DISubprogram(name: "unparse_name", linkageName: "_ZN7Handler12unparse_nameEP7ElementRK6String", scope: !1164, file: !1163, line: 216, type: !1243, scopeLine: 216, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1243 = !DISubroutineType(types: !1244)
!1244 = !{!554, !1175, !595}
!1245 = !DISubprogram(name: "blank_handler", linkageName: "_ZN7Handler13blank_handlerEv", scope: !1164, file: !1163, line: 223, type: !1246, scopeLine: 223, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1246 = !DISubroutineType(types: !1247)
!1247 = !{!1178}
!1248 = !DISubprogram(name: "__call_read", linkageName: "_ZNK7Handler11__call_readEP7ElementPv", scope: !1164, file: !1163, line: 281, type: !1249, scopeLine: 281, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1249 = !DISubroutineType(types: !1250)
!1250 = !{!554, !1206, !1175, !135}
!1251 = !DISubprogram(name: "Handler", scope: !1164, file: !1163, line: 306, type: !1252, scopeLine: 306, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1252 = !DISubroutineType(types: !1253)
!1253 = !{null, !1254, !595}
!1254 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1164, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1255 = !DISubprogram(name: "combine", linkageName: "_ZN7Handler7combineERKS_", scope: !1164, file: !1163, line: 308, type: !1256, scopeLine: 308, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1256 = !DISubroutineType(types: !1257)
!1257 = !{null, !1254, !1258}
!1258 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1179, size: 64)
!1259 = !DISubprogram(name: "compatible", linkageName: "_ZNK7Handler10compatibleERKS_", scope: !1164, file: !1163, line: 309, type: !1260, scopeLine: 309, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1260 = !DISubroutineType(types: !1261)
!1261 = !{!53, !1206, !1258}
!1262 = !{!1263, !1264, !1265, !1266, !1267, !1268, !1269, !1270, !1271, !1272}
!1263 = !DIEnumerator(name: "OP_READ", value: 1, isUnsigned: true)
!1264 = !DIEnumerator(name: "OP_WRITE", value: 2, isUnsigned: true)
!1265 = !DIEnumerator(name: "READ_PARAM", value: 4, isUnsigned: true)
!1266 = !DIEnumerator(name: "RAW", value: 64, isUnsigned: true)
!1267 = !DIEnumerator(name: "CALM", value: 2048, isUnsigned: true)
!1268 = !DIEnumerator(name: "EXPENSIVE", value: 4096, isUnsigned: true)
!1269 = !DIEnumerator(name: "BUTTON", value: 8192, isUnsigned: true)
!1270 = !DIEnumerator(name: "CHECKBOX", value: 16384, isUnsigned: true)
!1271 = !DIEnumerator(name: "USER_FLAG_SHIFT", value: 28, isUnsigned: true)
!1272 = !DIEnumerator(name: "USER_FLAG_0", value: 268435456, isUnsigned: true)
!1273 = !DICompositeType(tag: DW_TAG_enumeration_type, scope: !1275, file: !1274, line: 1014, baseType: !16, size: 32, elements: !1276, identifier: "_ZTSN6NumArgUt_E")
!1274 = !DIFile(filename: "../dummy_inc/click/args.hh", directory: "/home/john/projects/click/ir-dir")
!1275 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "NumArg", file: !1274, line: 1013, size: 8, flags: DIFlagTypePassByValue, elements: !452, identifier: "_ZTS6NumArg")
!1276 = !{!1277, !1278, !1279, !1280, !1281}
!1277 = !DIEnumerator(name: "status_ok", value: 0, isUnsigned: true)
!1278 = !DIEnumerator(name: "status_inval", value: 22, isUnsigned: true)
!1279 = !DIEnumerator(name: "status_range", value: 34, isUnsigned: true)
!1280 = !DIEnumerator(name: "status_notsup", value: 95, isUnsigned: true)
!1281 = !DIEnumerator(name: "status_unitless", value: 96, isUnsigned: true)
!1282 = !{!1283, !1653, !1813, !34, !1815, !53, !1287, !1858}
!1283 = !DISubprogram(name: "args_base_read<int>", linkageName: "_Z14args_base_readIiEvP4ArgsPKciRT_", scope: !1274, file: !1274, line: 928, type: !1284, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1722, retainedNodes: !452)
!1284 = !DISubroutineType(types: !1285)
!1285 = !{null, !1286, !566, !34, !1678}
!1286 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1287, size: 64)
!1287 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Args", file: !1274, line: 247, size: 896, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1288, identifier: "_ZTS4Args")
!1288 = !{!1289, !1329, !1331, !1332, !1333, !1334, !1335, !1336, !1337, !1534, !1723, !1726, !1727, !1731, !1734, !1737, !1740, !1745, !1748, !1752, !1756, !1757, !1760, !1763, !1766, !1767, !1768, !1769, !1770, !1774, !1777, !1778, !1779, !1780, !1781, !1784, !1785, !1786, !1790, !1793, !1797, !1800, !1801, !1804, !1810}
!1289 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !1287, baseType: !1290, flags: DIFlagPublic, extraData: i32 0)
!1290 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "ArgContext", file: !1274, line: 29, size: 256, flags: DIFlagTypePassByValue | DIFlagNonTrivial, elements: !1291, identifier: "_ZTS10ArgContext")
!1291 = !{!1292, !1295, !1296, !1297, !1298, !1302, !1305, !1310, !1313, !1316, !1319, !1320, !1321, !1324}
!1292 = !DIDerivedType(tag: DW_TAG_member, name: "_context", scope: !1290, file: !1274, line: 79, baseType: !1293, size: 64, flags: DIFlagProtected)
!1293 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1294, size: 64)
!1294 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1176)
!1295 = !DIDerivedType(tag: DW_TAG_member, name: "_errh", scope: !1290, file: !1274, line: 81, baseType: !1180, size: 64, offset: 64, flags: DIFlagProtected)
!1296 = !DIDerivedType(tag: DW_TAG_member, name: "_arg_keyword", scope: !1290, file: !1274, line: 82, baseType: !566, size: 64, offset: 128, flags: DIFlagProtected)
!1297 = !DIDerivedType(tag: DW_TAG_member, name: "_read_status", scope: !1290, file: !1274, line: 83, baseType: !53, size: 8, offset: 192, flags: DIFlagProtected)
!1298 = !DISubprogram(name: "ArgContext", scope: !1290, file: !1274, line: 33, type: !1299, scopeLine: 33, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1299 = !DISubroutineType(types: !1300)
!1300 = !{null, !1301, !1180}
!1301 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1290, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1302 = !DISubprogram(name: "ArgContext", scope: !1290, file: !1274, line: 44, type: !1303, scopeLine: 44, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1303 = !DISubroutineType(types: !1304)
!1304 = !{null, !1301, !1293, !1180}
!1305 = !DISubprogram(name: "context", linkageName: "_ZNK10ArgContext7contextEv", scope: !1290, file: !1274, line: 49, type: !1306, scopeLine: 49, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1306 = !DISubroutineType(types: !1307)
!1307 = !{!1293, !1308}
!1308 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1309, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1309 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1290)
!1310 = !DISubprogram(name: "errh", linkageName: "_ZNK10ArgContext4errhEv", scope: !1290, file: !1274, line: 55, type: !1311, scopeLine: 55, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1311 = !DISubroutineType(types: !1312)
!1312 = !{!1180, !1308}
!1313 = !DISubprogram(name: "error_prefix", linkageName: "_ZNK10ArgContext12error_prefixEv", scope: !1290, file: !1274, line: 62, type: !1314, scopeLine: 62, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1314 = !DISubroutineType(types: !1315)
!1315 = !{!554, !1308}
!1316 = !DISubprogram(name: "error", linkageName: "_ZNK10ArgContext5errorEPKcz", scope: !1290, file: !1274, line: 65, type: !1317, scopeLine: 65, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1317 = !DISubroutineType(types: !1318)
!1318 = !{null, !1308, !566, null}
!1319 = !DISubprogram(name: "warning", linkageName: "_ZNK10ArgContext7warningEPKcz", scope: !1290, file: !1274, line: 68, type: !1317, scopeLine: 68, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1320 = !DISubprogram(name: "message", linkageName: "_ZNK10ArgContext7messageEPKcz", scope: !1290, file: !1274, line: 71, type: !1317, scopeLine: 71, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1321 = !DISubprogram(name: "xmessage", linkageName: "_ZNK10ArgContext8xmessageERK6StringS2_", scope: !1290, file: !1274, line: 73, type: !1322, scopeLine: 73, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1322 = !DISubroutineType(types: !1323)
!1323 = !{null, !1308, !595, !595}
!1324 = !DISubprogram(name: "xmessage", linkageName: "_ZNK10ArgContext8xmessageERK6StringPKcP13__va_list_tag", scope: !1290, file: !1274, line: 74, type: !1325, scopeLine: 74, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1325 = !DISubroutineType(types: !1326)
!1326 = !{null, !1308, !595, !566, !1327}
!1327 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1328, size: 64)
!1328 = !DICompositeType(tag: DW_TAG_structure_type, name: "__va_list_tag", file: !1, line: 37, flags: DIFlagFwdDecl, identifier: "_ZTS13__va_list_tag")
!1329 = !DIDerivedType(tag: DW_TAG_member, name: "mandatory", scope: !1287, file: !1274, line: 356, baseType: !1330, flags: DIFlagPublic | DIFlagStaticMember, extraData: i32 1)
!1330 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !34)
!1331 = !DIDerivedType(tag: DW_TAG_member, name: "positional", scope: !1287, file: !1274, line: 357, baseType: !1330, flags: DIFlagPublic | DIFlagStaticMember, extraData: i32 2)
!1332 = !DIDerivedType(tag: DW_TAG_member, name: "deprecated", scope: !1287, file: !1274, line: 358, baseType: !1330, flags: DIFlagPublic | DIFlagStaticMember, extraData: i32 4)
!1333 = !DIDerivedType(tag: DW_TAG_member, name: "firstmatch", scope: !1287, file: !1274, line: 359, baseType: !1330, flags: DIFlagPublic | DIFlagStaticMember, extraData: i32 8)
!1334 = !DIDerivedType(tag: DW_TAG_member, name: "_my_conf", scope: !1287, file: !1274, line: 871, baseType: !53, size: 8, offset: 200)
!1335 = !DIDerivedType(tag: DW_TAG_member, name: "_status", scope: !1287, file: !1274, line: 876, baseType: !53, size: 8, offset: 208)
!1336 = !DIDerivedType(tag: DW_TAG_member, name: "_simple_slotpos", scope: !1287, file: !1274, line: 877, baseType: !98, size: 8, offset: 216)
!1337 = !DIDerivedType(tag: DW_TAG_member, name: "_conf", scope: !1287, file: !1274, line: 879, baseType: !1338, size: 64, offset: 256)
!1338 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1339, size: 64)
!1339 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Vector<String>", file: !1340, line: 111, size: 128, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1341, templateParams: !1376, identifier: "_ZTS6VectorI6StringE")
!1340 = !DIFile(filename: "../dummy_inc/click/vector.hh", directory: "/home/john/projects/click/ir-dir")
!1341 = !{!1342, !1429, !1433, !1446, !1451, !1455, !1459, !1462, !1465, !1469, !1470, !1475, !1476, !1477, !1478, !1481, !1482, !1485, !1486, !1489, !1492, !1495, !1496, !1497, !1500, !1503, !1504, !1505, !1506, !1507, !1508, !1509, !1512, !1515, !1518, !1519, !1520, !1521, !1524, !1527, !1530, !1531}
!1342 = !DIDerivedType(tag: DW_TAG_member, name: "vm_", scope: !1339, file: !1340, line: 114, baseType: !1343, size: 128)
!1343 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "vector_memory<typed_array_memory<String> >", file: !1340, line: 11, size: 128, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1344, templateParams: !1427, identifier: "_ZTS13vector_memoryI18typed_array_memoryI6StringEE")
!1344 = !{!1345, !1378, !1380, !1381, !1388, !1392, !1393, !1397, !1400, !1401, !1405, !1406, !1409, !1412, !1415, !1418, !1419, !1420, !1423}
!1345 = !DIDerivedType(tag: DW_TAG_member, name: "l_", scope: !1343, file: !1340, line: 68, baseType: !1346, size: 64, flags: DIFlagPublic)
!1346 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1347, size: 64)
!1347 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1343, file: !1340, line: 13, baseType: !1348)
!1348 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1350, file: !1349, line: 58, baseType: !554)
!1349 = !DIFile(filename: "../dummy_inc/click/array_memory.hh", directory: "/home/john/projects/click/ir-dir")
!1350 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "typed_array_memory<String>", file: !1349, line: 57, size: 8, flags: DIFlagTypePassByValue, elements: !1351, templateParams: !1376, identifier: "_ZTS18typed_array_memoryI6StringE")
!1351 = !{!1352, !1356, !1360, !1363, !1366, !1369, !1370, !1371, !1374, !1375}
!1352 = !DISubprogram(name: "cast", linkageName: "_ZN18typed_array_memoryI6StringE4castEPS0_", scope: !1350, file: !1349, line: 59, type: !1353, scopeLine: 59, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1353 = !DISubroutineType(types: !1354)
!1354 = !{!1355, !1355}
!1355 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !554, size: 64)
!1356 = !DISubprogram(name: "cast", linkageName: "_ZN18typed_array_memoryI6StringE4castEPKS0_", scope: !1350, file: !1349, line: 62, type: !1357, scopeLine: 62, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1357 = !DISubroutineType(types: !1358)
!1358 = !{!1359, !1359}
!1359 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !596, size: 64)
!1360 = !DISubprogram(name: "fill", linkageName: "_ZN18typed_array_memoryI6StringE4fillEPS0_mPKS0_", scope: !1350, file: !1349, line: 65, type: !1361, scopeLine: 65, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1361 = !DISubroutineType(types: !1362)
!1362 = !{null, !1355, !133, !1359}
!1363 = !DISubprogram(name: "move_construct", linkageName: "_ZN18typed_array_memoryI6StringE14move_constructEPS0_S2_", scope: !1350, file: !1349, line: 69, type: !1364, scopeLine: 69, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1364 = !DISubroutineType(types: !1365)
!1365 = !{null, !1355, !1355}
!1366 = !DISubprogram(name: "copy", linkageName: "_ZN18typed_array_memoryI6StringE4copyEPS0_PKS0_m", scope: !1350, file: !1349, line: 76, type: !1367, scopeLine: 76, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1367 = !DISubroutineType(types: !1368)
!1368 = !{null, !1355, !1359, !133}
!1369 = !DISubprogram(name: "move", linkageName: "_ZN18typed_array_memoryI6StringE4moveEPS0_PKS0_m", scope: !1350, file: !1349, line: 80, type: !1367, scopeLine: 80, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1370 = !DISubprogram(name: "move_onto", linkageName: "_ZN18typed_array_memoryI6StringE9move_ontoEPS0_PKS0_m", scope: !1350, file: !1349, line: 93, type: !1367, scopeLine: 93, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1371 = !DISubprogram(name: "destroy", linkageName: "_ZN18typed_array_memoryI6StringE7destroyEPS0_m", scope: !1350, file: !1349, line: 106, type: !1372, scopeLine: 106, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1372 = !DISubroutineType(types: !1373)
!1373 = !{null, !1355, !133}
!1374 = !DISubprogram(name: "mark_noaccess", linkageName: "_ZN18typed_array_memoryI6StringE13mark_noaccessEPS0_m", scope: !1350, file: !1349, line: 110, type: !1372, scopeLine: 110, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1375 = !DISubprogram(name: "mark_undefined", linkageName: "_ZN18typed_array_memoryI6StringE14mark_undefinedEPS0_m", scope: !1350, file: !1349, line: 113, type: !1372, scopeLine: 113, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1376 = !{!1377}
!1377 = !DITemplateTypeParameter(name: "T", type: !554)
!1378 = !DIDerivedType(tag: DW_TAG_member, name: "n_", scope: !1343, file: !1340, line: 69, baseType: !1379, size: 32, offset: 64, flags: DIFlagPublic)
!1379 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", file: !1340, line: 12, baseType: !34)
!1380 = !DIDerivedType(tag: DW_TAG_member, name: "capacity_", scope: !1343, file: !1340, line: 70, baseType: !1379, size: 32, offset: 96, flags: DIFlagPublic)
!1381 = !DISubprogram(name: "need_argument_copy", linkageName: "_ZNK13vector_memoryI18typed_array_memoryI6StringEE18need_argument_copyEPKS1_", scope: !1343, file: !1340, line: 15, type: !1382, scopeLine: 15, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1382 = !DISubroutineType(types: !1383)
!1383 = !{!53, !1384, !1386}
!1384 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1385, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1385 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1343)
!1386 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1387, size: 64)
!1387 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1347)
!1388 = !DISubprogram(name: "vector_memory", scope: !1343, file: !1340, line: 20, type: !1389, scopeLine: 20, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1389 = !DISubroutineType(types: !1390)
!1390 = !{null, !1391}
!1391 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1343, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1392 = !DISubprogram(name: "~vector_memory", scope: !1343, file: !1340, line: 23, type: !1389, scopeLine: 23, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1393 = !DISubprogram(name: "assign", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE6assignERKS3_", scope: !1343, file: !1340, line: 25, type: !1394, scopeLine: 25, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1394 = !DISubroutineType(types: !1395)
!1395 = !{null, !1391, !1396}
!1396 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1385, size: 64)
!1397 = !DISubprogram(name: "assign", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE6assignEiPKS1_", scope: !1343, file: !1340, line: 26, type: !1398, scopeLine: 26, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1398 = !DISubroutineType(types: !1399)
!1399 = !{null, !1391, !1379, !1386}
!1400 = !DISubprogram(name: "resize", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE6resizeEiPKS1_", scope: !1343, file: !1340, line: 27, type: !1398, scopeLine: 27, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1401 = !DISubprogram(name: "begin", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE5beginEv", scope: !1343, file: !1340, line: 28, type: !1402, scopeLine: 28, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1402 = !DISubroutineType(types: !1403)
!1403 = !{!1404, !1391}
!1404 = !DIDerivedType(tag: DW_TAG_typedef, name: "iterator", scope: !1343, file: !1340, line: 14, baseType: !1346)
!1405 = !DISubprogram(name: "end", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE3endEv", scope: !1343, file: !1340, line: 31, type: !1402, scopeLine: 31, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1406 = !DISubprogram(name: "insert", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE6insertEPS1_PKS1_", scope: !1343, file: !1340, line: 34, type: !1407, scopeLine: 34, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1407 = !DISubroutineType(types: !1408)
!1408 = !{!1404, !1391, !1404, !1386}
!1409 = !DISubprogram(name: "erase", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE5eraseEPS1_S4_", scope: !1343, file: !1340, line: 35, type: !1410, scopeLine: 35, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1410 = !DISubroutineType(types: !1411)
!1411 = !{!1404, !1391, !1404, !1404}
!1412 = !DISubprogram(name: "push_back", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE9push_backEPKS1_", scope: !1343, file: !1340, line: 36, type: !1413, scopeLine: 36, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1413 = !DISubroutineType(types: !1414)
!1414 = !{null, !1391, !1386}
!1415 = !DISubprogram(name: "move_construct_back", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE19move_construct_backEPS1_", scope: !1343, file: !1340, line: 45, type: !1416, scopeLine: 45, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1416 = !DISubroutineType(types: !1417)
!1417 = !{null, !1391, !1346}
!1418 = !DISubprogram(name: "pop_back", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE8pop_backEv", scope: !1343, file: !1340, line: 54, type: !1389, scopeLine: 54, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1419 = !DISubprogram(name: "clear", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE5clearEv", scope: !1343, file: !1340, line: 60, type: !1389, scopeLine: 60, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1420 = !DISubprogram(name: "reserve_and_push_back", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE21reserve_and_push_backEiPKS1_", scope: !1343, file: !1340, line: 65, type: !1421, scopeLine: 65, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1421 = !DISubroutineType(types: !1422)
!1422 = !{!53, !1391, !1379, !1386}
!1423 = !DISubprogram(name: "swap", linkageName: "_ZN13vector_memoryI18typed_array_memoryI6StringEE4swapERS3_", scope: !1343, file: !1340, line: 66, type: !1424, scopeLine: 66, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1424 = !DISubroutineType(types: !1425)
!1425 = !{null, !1391, !1426}
!1426 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1343, size: 64)
!1427 = !{!1428}
!1428 = !DITemplateTypeParameter(name: "AM", type: !1350)
!1429 = !DISubprogram(name: "Vector", scope: !1339, file: !1340, line: 137, type: !1430, scopeLine: 137, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1430 = !DISubroutineType(types: !1431)
!1431 = !{null, !1432}
!1432 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1339, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1433 = !DISubprogram(name: "Vector", scope: !1339, file: !1340, line: 138, type: !1434, scopeLine: 138, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1434 = !DISubroutineType(types: !1435)
!1435 = !{null, !1432, !1436, !1437}
!1436 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", file: !1340, line: 128, baseType: !34)
!1437 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_argument_type", scope: !1339, file: !1340, line: 125, baseType: !1438)
!1438 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1440, file: !1439, line: 150, baseType: !595)
!1439 = !DIFile(filename: "../dummy_inc/click/type_traits.hh", directory: "/home/john/projects/click/ir-dir")
!1440 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "fast_argument<String, true>", file: !1439, line: 148, size: 8, flags: DIFlagTypePassByValue, elements: !1441, templateParams: !1444, identifier: "_ZTS13fast_argumentI6StringLb1EE")
!1441 = !{!1442}
!1442 = !DIDerivedType(tag: DW_TAG_member, name: "is_reference", scope: !1440, file: !1439, line: 149, baseType: !1443, flags: DIFlagStaticMember, extraData: i1 true)
!1443 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !53)
!1444 = !{!1377, !1445}
!1445 = !DITemplateValueParameter(name: "use_reference", type: !53, value: i8 1)
!1446 = !DISubprogram(name: "Vector", scope: !1339, file: !1340, line: 139, type: !1447, scopeLine: 139, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1447 = !DISubroutineType(types: !1448)
!1448 = !{null, !1432, !1449}
!1449 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1450, size: 64)
!1450 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1339)
!1451 = !DISubprogram(name: "Vector", scope: !1339, file: !1340, line: 141, type: !1452, scopeLine: 141, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1452 = !DISubroutineType(types: !1453)
!1453 = !{null, !1432, !1454}
!1454 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !1339, size: 64)
!1455 = !DISubprogram(name: "operator=", linkageName: "_ZN6VectorI6StringEaSERKS1_", scope: !1339, file: !1340, line: 144, type: !1456, scopeLine: 144, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1456 = !DISubroutineType(types: !1457)
!1457 = !{!1458, !1432, !1449}
!1458 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1339, size: 64)
!1459 = !DISubprogram(name: "operator=", linkageName: "_ZN6VectorI6StringEaSEOS1_", scope: !1339, file: !1340, line: 146, type: !1460, scopeLine: 146, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1460 = !DISubroutineType(types: !1461)
!1461 = !{!1458, !1432, !1454}
!1462 = !DISubprogram(name: "assign", linkageName: "_ZN6VectorI6StringE6assignEiRKS0_", scope: !1339, file: !1340, line: 148, type: !1463, scopeLine: 148, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1463 = !DISubroutineType(types: !1464)
!1464 = !{!1458, !1432, !1436, !1437}
!1465 = !DISubprogram(name: "begin", linkageName: "_ZN6VectorI6StringE5beginEv", scope: !1339, file: !1340, line: 150, type: !1466, scopeLine: 150, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1466 = !DISubroutineType(types: !1467)
!1467 = !{!1468, !1432}
!1468 = !DIDerivedType(tag: DW_TAG_typedef, name: "iterator", scope: !1339, file: !1340, line: 130, baseType: !1355)
!1469 = !DISubprogram(name: "end", linkageName: "_ZN6VectorI6StringE3endEv", scope: !1339, file: !1340, line: 151, type: !1466, scopeLine: 151, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1470 = !DISubprogram(name: "begin", linkageName: "_ZNK6VectorI6StringE5beginEv", scope: !1339, file: !1340, line: 152, type: !1471, scopeLine: 152, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1471 = !DISubroutineType(types: !1472)
!1472 = !{!1473, !1474}
!1473 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_iterator", scope: !1339, file: !1340, line: 131, baseType: !1359)
!1474 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1450, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1475 = !DISubprogram(name: "end", linkageName: "_ZNK6VectorI6StringE3endEv", scope: !1339, file: !1340, line: 153, type: !1471, scopeLine: 153, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1476 = !DISubprogram(name: "cbegin", linkageName: "_ZNK6VectorI6StringE6cbeginEv", scope: !1339, file: !1340, line: 154, type: !1471, scopeLine: 154, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1477 = !DISubprogram(name: "cend", linkageName: "_ZNK6VectorI6StringE4cendEv", scope: !1339, file: !1340, line: 155, type: !1471, scopeLine: 155, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1478 = !DISubprogram(name: "size", linkageName: "_ZNK6VectorI6StringE4sizeEv", scope: !1339, file: !1340, line: 157, type: !1479, scopeLine: 157, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1479 = !DISubroutineType(types: !1480)
!1480 = !{!1436, !1474}
!1481 = !DISubprogram(name: "capacity", linkageName: "_ZNK6VectorI6StringE8capacityEv", scope: !1339, file: !1340, line: 158, type: !1479, scopeLine: 158, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1482 = !DISubprogram(name: "empty", linkageName: "_ZNK6VectorI6StringE5emptyEv", scope: !1339, file: !1340, line: 159, type: !1483, scopeLine: 159, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1483 = !DISubroutineType(types: !1484)
!1484 = !{!53, !1474}
!1485 = !DISubprogram(name: "resize", linkageName: "_ZN6VectorI6StringE6resizeEiRKS0_", scope: !1339, file: !1340, line: 160, type: !1434, scopeLine: 160, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1486 = !DISubprogram(name: "reserve", linkageName: "_ZN6VectorI6StringE7reserveEi", scope: !1339, file: !1340, line: 161, type: !1487, scopeLine: 161, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1487 = !DISubroutineType(types: !1488)
!1488 = !{!53, !1432, !1436}
!1489 = !DISubprogram(name: "operator[]", linkageName: "_ZN6VectorI6StringEixEi", scope: !1339, file: !1340, line: 163, type: !1490, scopeLine: 163, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1490 = !DISubroutineType(types: !1491)
!1491 = !{!757, !1432, !1436}
!1492 = !DISubprogram(name: "operator[]", linkageName: "_ZNK6VectorI6StringEixEi", scope: !1339, file: !1340, line: 164, type: !1493, scopeLine: 164, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1493 = !DISubroutineType(types: !1494)
!1494 = !{!595, !1474, !1436}
!1495 = !DISubprogram(name: "at", linkageName: "_ZN6VectorI6StringE2atEi", scope: !1339, file: !1340, line: 165, type: !1490, scopeLine: 165, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1496 = !DISubprogram(name: "at", linkageName: "_ZNK6VectorI6StringE2atEi", scope: !1339, file: !1340, line: 166, type: !1493, scopeLine: 166, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1497 = !DISubprogram(name: "front", linkageName: "_ZN6VectorI6StringE5frontEv", scope: !1339, file: !1340, line: 167, type: !1498, scopeLine: 167, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1498 = !DISubroutineType(types: !1499)
!1499 = !{!757, !1432}
!1500 = !DISubprogram(name: "front", linkageName: "_ZNK6VectorI6StringE5frontEv", scope: !1339, file: !1340, line: 168, type: !1501, scopeLine: 168, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1501 = !DISubroutineType(types: !1502)
!1502 = !{!595, !1474}
!1503 = !DISubprogram(name: "back", linkageName: "_ZN6VectorI6StringE4backEv", scope: !1339, file: !1340, line: 169, type: !1498, scopeLine: 169, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1504 = !DISubprogram(name: "back", linkageName: "_ZNK6VectorI6StringE4backEv", scope: !1339, file: !1340, line: 170, type: !1501, scopeLine: 170, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1505 = !DISubprogram(name: "unchecked_at", linkageName: "_ZN6VectorI6StringE12unchecked_atEi", scope: !1339, file: !1340, line: 172, type: !1490, scopeLine: 172, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1506 = !DISubprogram(name: "unchecked_at", linkageName: "_ZNK6VectorI6StringE12unchecked_atEi", scope: !1339, file: !1340, line: 173, type: !1493, scopeLine: 173, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1507 = !DISubprogram(name: "at_u", linkageName: "_ZN6VectorI6StringE4at_uEi", scope: !1339, file: !1340, line: 174, type: !1490, scopeLine: 174, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1508 = !DISubprogram(name: "at_u", linkageName: "_ZNK6VectorI6StringE4at_uEi", scope: !1339, file: !1340, line: 175, type: !1493, scopeLine: 175, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1509 = !DISubprogram(name: "data", linkageName: "_ZN6VectorI6StringE4dataEv", scope: !1339, file: !1340, line: 177, type: !1510, scopeLine: 177, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1510 = !DISubroutineType(types: !1511)
!1511 = !{!1355, !1432}
!1512 = !DISubprogram(name: "data", linkageName: "_ZNK6VectorI6StringE4dataEv", scope: !1339, file: !1340, line: 178, type: !1513, scopeLine: 178, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1513 = !DISubroutineType(types: !1514)
!1514 = !{!1359, !1474}
!1515 = !DISubprogram(name: "push_back", linkageName: "_ZN6VectorI6StringE9push_backERKS0_", scope: !1339, file: !1340, line: 180, type: !1516, scopeLine: 180, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1516 = !DISubroutineType(types: !1517)
!1517 = !{null, !1432, !1437}
!1518 = !DISubprogram(name: "pop_back", linkageName: "_ZN6VectorI6StringE8pop_backEv", scope: !1339, file: !1340, line: 185, type: !1430, scopeLine: 185, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1519 = !DISubprogram(name: "push_front", linkageName: "_ZN6VectorI6StringE10push_frontERKS0_", scope: !1339, file: !1340, line: 186, type: !1516, scopeLine: 186, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1520 = !DISubprogram(name: "pop_front", linkageName: "_ZN6VectorI6StringE9pop_frontEv", scope: !1339, file: !1340, line: 187, type: !1430, scopeLine: 187, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1521 = !DISubprogram(name: "insert", linkageName: "_ZN6VectorI6StringE6insertEPS0_RKS0_", scope: !1339, file: !1340, line: 189, type: !1522, scopeLine: 189, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1522 = !DISubroutineType(types: !1523)
!1523 = !{!1468, !1432, !1468, !1437}
!1524 = !DISubprogram(name: "erase", linkageName: "_ZN6VectorI6StringE5eraseEPS0_", scope: !1339, file: !1340, line: 190, type: !1525, scopeLine: 190, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1525 = !DISubroutineType(types: !1526)
!1526 = !{!1468, !1432, !1468}
!1527 = !DISubprogram(name: "erase", linkageName: "_ZN6VectorI6StringE5eraseEPS0_S2_", scope: !1339, file: !1340, line: 191, type: !1528, scopeLine: 191, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1528 = !DISubroutineType(types: !1529)
!1529 = !{!1468, !1432, !1468, !1468}
!1530 = !DISubprogram(name: "clear", linkageName: "_ZN6VectorI6StringE5clearEv", scope: !1339, file: !1340, line: 193, type: !1430, scopeLine: 193, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1531 = !DISubprogram(name: "swap", linkageName: "_ZN6VectorI6StringE4swapERS1_", scope: !1339, file: !1340, line: 195, type: !1532, scopeLine: 195, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1532 = !DISubroutineType(types: !1533)
!1533 = !{null, !1432, !1458}
!1534 = !DIDerivedType(tag: DW_TAG_member, name: "_kwpos", scope: !1287, file: !1274, line: 880, baseType: !1535, size: 128, offset: 320)
!1535 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Vector<int>", file: !1340, line: 111, size: 128, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1536, templateParams: !1722, identifier: "_ZTS6VectorIiE")
!1536 = !{!1537, !1615, !1619, !1630, !1635, !1639, !1643, !1646, !1649, !1654, !1655, !1661, !1662, !1663, !1664, !1667, !1668, !1671, !1672, !1675, !1679, !1683, !1684, !1685, !1688, !1691, !1692, !1693, !1694, !1695, !1696, !1697, !1700, !1703, !1706, !1707, !1708, !1709, !1712, !1715, !1718, !1719}
!1537 = !DIDerivedType(tag: DW_TAG_member, name: "vm_", scope: !1535, file: !1340, line: 114, baseType: !1538, size: 128)
!1538 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "vector_memory<sized_array_memory<4> >", file: !1340, line: 11, size: 128, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1539, templateParams: !1613, identifier: "_ZTS13vector_memoryI18sized_array_memoryILm4EEE")
!1539 = !{!1540, !1565, !1566, !1567, !1574, !1578, !1579, !1583, !1586, !1587, !1591, !1592, !1595, !1598, !1601, !1604, !1605, !1606, !1609}
!1540 = !DIDerivedType(tag: DW_TAG_member, name: "l_", scope: !1538, file: !1340, line: 68, baseType: !1541, size: 64, flags: DIFlagPublic)
!1541 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1542, size: 64)
!1542 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1538, file: !1340, line: 13, baseType: !1543)
!1543 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1544, file: !1349, line: 11, baseType: !1564)
!1544 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "sized_array_memory<4>", file: !1349, line: 10, size: 8, flags: DIFlagTypePassByValue, elements: !1545, templateParams: !1562, identifier: "_ZTS18sized_array_memoryILm4EE")
!1545 = !{!1546, !1549, !1552, !1555, !1556, !1557, !1560, !1561}
!1546 = !DISubprogram(name: "fill", linkageName: "_ZN18sized_array_memoryILm4EE4fillEPvmPKv", scope: !1544, file: !1349, line: 19, type: !1547, scopeLine: 19, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1547 = !DISubroutineType(types: !1548)
!1548 = !{null, !135, !133, !224}
!1549 = !DISubprogram(name: "move_construct", linkageName: "_ZN18sized_array_memoryILm4EE14move_constructEPvS1_", scope: !1544, file: !1349, line: 23, type: !1550, scopeLine: 23, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1550 = !DISubroutineType(types: !1551)
!1551 = !{null, !135, !135}
!1552 = !DISubprogram(name: "copy", linkageName: "_ZN18sized_array_memoryILm4EE4copyEPvPKvm", scope: !1544, file: !1349, line: 26, type: !1553, scopeLine: 26, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1553 = !DISubroutineType(types: !1554)
!1554 = !{null, !135, !224, !133}
!1555 = !DISubprogram(name: "move", linkageName: "_ZN18sized_array_memoryILm4EE4moveEPvPKvm", scope: !1544, file: !1349, line: 30, type: !1553, scopeLine: 30, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1556 = !DISubprogram(name: "move_onto", linkageName: "_ZN18sized_array_memoryILm4EE9move_ontoEPvPKvm", scope: !1544, file: !1349, line: 34, type: !1553, scopeLine: 34, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1557 = !DISubprogram(name: "destroy", linkageName: "_ZN18sized_array_memoryILm4EE7destroyEPvm", scope: !1544, file: !1349, line: 38, type: !1558, scopeLine: 38, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1558 = !DISubroutineType(types: !1559)
!1559 = !{null, !135, !133}
!1560 = !DISubprogram(name: "mark_noaccess", linkageName: "_ZN18sized_array_memoryILm4EE13mark_noaccessEPvm", scope: !1544, file: !1349, line: 41, type: !1558, scopeLine: 41, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1561 = !DISubprogram(name: "mark_undefined", linkageName: "_ZN18sized_array_memoryILm4EE14mark_undefinedEPvm", scope: !1544, file: !1349, line: 48, type: !1558, scopeLine: 48, flags: DIFlagPublic | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1562 = !{!1563}
!1563 = !DITemplateValueParameter(name: "s", type: !115, value: i64 4)
!1564 = !DICompositeType(tag: DW_TAG_structure_type, name: "char_array<4>", file: !1439, line: 165, flags: DIFlagFwdDecl, identifier: "_ZTS10char_arrayILm4EE")
!1565 = !DIDerivedType(tag: DW_TAG_member, name: "n_", scope: !1538, file: !1340, line: 69, baseType: !1379, size: 32, offset: 64, flags: DIFlagPublic)
!1566 = !DIDerivedType(tag: DW_TAG_member, name: "capacity_", scope: !1538, file: !1340, line: 70, baseType: !1379, size: 32, offset: 96, flags: DIFlagPublic)
!1567 = !DISubprogram(name: "need_argument_copy", linkageName: "_ZNK13vector_memoryI18sized_array_memoryILm4EEE18need_argument_copyEPK10char_arrayILm4EE", scope: !1538, file: !1340, line: 15, type: !1568, scopeLine: 15, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1568 = !DISubroutineType(types: !1569)
!1569 = !{!53, !1570, !1572}
!1570 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1571, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1571 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1538)
!1572 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1573, size: 64)
!1573 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1542)
!1574 = !DISubprogram(name: "vector_memory", scope: !1538, file: !1340, line: 20, type: !1575, scopeLine: 20, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1575 = !DISubroutineType(types: !1576)
!1576 = !{null, !1577}
!1577 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1538, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1578 = !DISubprogram(name: "~vector_memory", scope: !1538, file: !1340, line: 23, type: !1575, scopeLine: 23, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1579 = !DISubprogram(name: "assign", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE6assignERKS2_", scope: !1538, file: !1340, line: 25, type: !1580, scopeLine: 25, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1580 = !DISubroutineType(types: !1581)
!1581 = !{null, !1577, !1582}
!1582 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1571, size: 64)
!1583 = !DISubprogram(name: "assign", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE6assignEiPK10char_arrayILm4EE", scope: !1538, file: !1340, line: 26, type: !1584, scopeLine: 26, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1584 = !DISubroutineType(types: !1585)
!1585 = !{null, !1577, !1379, !1572}
!1586 = !DISubprogram(name: "resize", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE6resizeEiPK10char_arrayILm4EE", scope: !1538, file: !1340, line: 27, type: !1584, scopeLine: 27, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1587 = !DISubprogram(name: "begin", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE5beginEv", scope: !1538, file: !1340, line: 28, type: !1588, scopeLine: 28, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1588 = !DISubroutineType(types: !1589)
!1589 = !{!1590, !1577}
!1590 = !DIDerivedType(tag: DW_TAG_typedef, name: "iterator", scope: !1538, file: !1340, line: 14, baseType: !1541)
!1591 = !DISubprogram(name: "end", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE3endEv", scope: !1538, file: !1340, line: 31, type: !1588, scopeLine: 31, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1592 = !DISubprogram(name: "insert", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE6insertEP10char_arrayILm4EEPKS4_", scope: !1538, file: !1340, line: 34, type: !1593, scopeLine: 34, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1593 = !DISubroutineType(types: !1594)
!1594 = !{!1590, !1577, !1590, !1572}
!1595 = !DISubprogram(name: "erase", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE5eraseEP10char_arrayILm4EES5_", scope: !1538, file: !1340, line: 35, type: !1596, scopeLine: 35, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1596 = !DISubroutineType(types: !1597)
!1597 = !{!1590, !1577, !1590, !1590}
!1598 = !DISubprogram(name: "push_back", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE9push_backEPK10char_arrayILm4EE", scope: !1538, file: !1340, line: 36, type: !1599, scopeLine: 36, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1599 = !DISubroutineType(types: !1600)
!1600 = !{null, !1577, !1572}
!1601 = !DISubprogram(name: "move_construct_back", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE19move_construct_backEP10char_arrayILm4EE", scope: !1538, file: !1340, line: 45, type: !1602, scopeLine: 45, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1602 = !DISubroutineType(types: !1603)
!1603 = !{null, !1577, !1541}
!1604 = !DISubprogram(name: "pop_back", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE8pop_backEv", scope: !1538, file: !1340, line: 54, type: !1575, scopeLine: 54, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1605 = !DISubprogram(name: "clear", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE5clearEv", scope: !1538, file: !1340, line: 60, type: !1575, scopeLine: 60, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1606 = !DISubprogram(name: "reserve_and_push_back", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE21reserve_and_push_backEiPK10char_arrayILm4EE", scope: !1538, file: !1340, line: 65, type: !1607, scopeLine: 65, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1607 = !DISubroutineType(types: !1608)
!1608 = !{!53, !1577, !1379, !1572}
!1609 = !DISubprogram(name: "swap", linkageName: "_ZN13vector_memoryI18sized_array_memoryILm4EEE4swapERS2_", scope: !1538, file: !1340, line: 66, type: !1610, scopeLine: 66, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1610 = !DISubroutineType(types: !1611)
!1611 = !{null, !1577, !1612}
!1612 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1538, size: 64)
!1613 = !{!1614}
!1614 = !DITemplateTypeParameter(name: "AM", type: !1544)
!1615 = !DISubprogram(name: "Vector", scope: !1535, file: !1340, line: 137, type: !1616, scopeLine: 137, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1616 = !DISubroutineType(types: !1617)
!1617 = !{null, !1618}
!1618 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1535, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1619 = !DISubprogram(name: "Vector", scope: !1535, file: !1340, line: 138, type: !1620, scopeLine: 138, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1620 = !DISubroutineType(types: !1621)
!1621 = !{null, !1618, !1436, !1622}
!1622 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_argument_type", scope: !1535, file: !1340, line: 125, baseType: !1623)
!1623 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1624, file: !1439, line: 157, baseType: !34)
!1624 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "fast_argument<int, false>", file: !1439, line: 155, size: 8, flags: DIFlagTypePassByValue, elements: !1625, templateParams: !1627, identifier: "_ZTS13fast_argumentIiLb0EE")
!1625 = !{!1626}
!1626 = !DIDerivedType(tag: DW_TAG_member, name: "is_reference", scope: !1624, file: !1439, line: 156, baseType: !1443, flags: DIFlagStaticMember, extraData: i1 false)
!1627 = !{!1628, !1629}
!1628 = !DITemplateTypeParameter(name: "T", type: !34)
!1629 = !DITemplateValueParameter(name: "use_reference", type: !53, value: i8 0)
!1630 = !DISubprogram(name: "Vector", scope: !1535, file: !1340, line: 139, type: !1631, scopeLine: 139, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1631 = !DISubroutineType(types: !1632)
!1632 = !{null, !1618, !1633}
!1633 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1634, size: 64)
!1634 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1535)
!1635 = !DISubprogram(name: "Vector", scope: !1535, file: !1340, line: 141, type: !1636, scopeLine: 141, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1636 = !DISubroutineType(types: !1637)
!1637 = !{null, !1618, !1638}
!1638 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !1535, size: 64)
!1639 = !DISubprogram(name: "operator=", linkageName: "_ZN6VectorIiEaSERKS0_", scope: !1535, file: !1340, line: 144, type: !1640, scopeLine: 144, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1640 = !DISubroutineType(types: !1641)
!1641 = !{!1642, !1618, !1633}
!1642 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1535, size: 64)
!1643 = !DISubprogram(name: "operator=", linkageName: "_ZN6VectorIiEaSEOS0_", scope: !1535, file: !1340, line: 146, type: !1644, scopeLine: 146, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1644 = !DISubroutineType(types: !1645)
!1645 = !{!1642, !1618, !1638}
!1646 = !DISubprogram(name: "assign", linkageName: "_ZN6VectorIiE6assignEii", scope: !1535, file: !1340, line: 148, type: !1647, scopeLine: 148, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1647 = !DISubroutineType(types: !1648)
!1648 = !{!1642, !1618, !1436, !1622}
!1649 = !DISubprogram(name: "begin", linkageName: "_ZN6VectorIiE5beginEv", scope: !1535, file: !1340, line: 150, type: !1650, scopeLine: 150, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1650 = !DISubroutineType(types: !1651)
!1651 = !{!1652, !1618}
!1652 = !DIDerivedType(tag: DW_TAG_typedef, name: "iterator", scope: !1535, file: !1340, line: 130, baseType: !1653)
!1653 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!1654 = !DISubprogram(name: "end", linkageName: "_ZN6VectorIiE3endEv", scope: !1535, file: !1340, line: 151, type: !1650, scopeLine: 151, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1655 = !DISubprogram(name: "begin", linkageName: "_ZNK6VectorIiE5beginEv", scope: !1535, file: !1340, line: 152, type: !1656, scopeLine: 152, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1656 = !DISubroutineType(types: !1657)
!1657 = !{!1658, !1660}
!1658 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_iterator", scope: !1535, file: !1340, line: 131, baseType: !1659)
!1659 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1330, size: 64)
!1660 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1634, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1661 = !DISubprogram(name: "end", linkageName: "_ZNK6VectorIiE3endEv", scope: !1535, file: !1340, line: 153, type: !1656, scopeLine: 153, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1662 = !DISubprogram(name: "cbegin", linkageName: "_ZNK6VectorIiE6cbeginEv", scope: !1535, file: !1340, line: 154, type: !1656, scopeLine: 154, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1663 = !DISubprogram(name: "cend", linkageName: "_ZNK6VectorIiE4cendEv", scope: !1535, file: !1340, line: 155, type: !1656, scopeLine: 155, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1664 = !DISubprogram(name: "size", linkageName: "_ZNK6VectorIiE4sizeEv", scope: !1535, file: !1340, line: 157, type: !1665, scopeLine: 157, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1665 = !DISubroutineType(types: !1666)
!1666 = !{!1436, !1660}
!1667 = !DISubprogram(name: "capacity", linkageName: "_ZNK6VectorIiE8capacityEv", scope: !1535, file: !1340, line: 158, type: !1665, scopeLine: 158, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1668 = !DISubprogram(name: "empty", linkageName: "_ZNK6VectorIiE5emptyEv", scope: !1535, file: !1340, line: 159, type: !1669, scopeLine: 159, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1669 = !DISubroutineType(types: !1670)
!1670 = !{!53, !1660}
!1671 = !DISubprogram(name: "resize", linkageName: "_ZN6VectorIiE6resizeEii", scope: !1535, file: !1340, line: 160, type: !1620, scopeLine: 160, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1672 = !DISubprogram(name: "reserve", linkageName: "_ZN6VectorIiE7reserveEi", scope: !1535, file: !1340, line: 161, type: !1673, scopeLine: 161, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1673 = !DISubroutineType(types: !1674)
!1674 = !{!53, !1618, !1436}
!1675 = !DISubprogram(name: "operator[]", linkageName: "_ZN6VectorIiEixEi", scope: !1535, file: !1340, line: 163, type: !1676, scopeLine: 163, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1676 = !DISubroutineType(types: !1677)
!1677 = !{!1678, !1618, !1436}
!1678 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !34, size: 64)
!1679 = !DISubprogram(name: "operator[]", linkageName: "_ZNK6VectorIiEixEi", scope: !1535, file: !1340, line: 164, type: !1680, scopeLine: 164, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1680 = !DISubroutineType(types: !1681)
!1681 = !{!1682, !1660, !1436}
!1682 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1330, size: 64)
!1683 = !DISubprogram(name: "at", linkageName: "_ZN6VectorIiE2atEi", scope: !1535, file: !1340, line: 165, type: !1676, scopeLine: 165, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1684 = !DISubprogram(name: "at", linkageName: "_ZNK6VectorIiE2atEi", scope: !1535, file: !1340, line: 166, type: !1680, scopeLine: 166, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1685 = !DISubprogram(name: "front", linkageName: "_ZN6VectorIiE5frontEv", scope: !1535, file: !1340, line: 167, type: !1686, scopeLine: 167, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1686 = !DISubroutineType(types: !1687)
!1687 = !{!1678, !1618}
!1688 = !DISubprogram(name: "front", linkageName: "_ZNK6VectorIiE5frontEv", scope: !1535, file: !1340, line: 168, type: !1689, scopeLine: 168, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1689 = !DISubroutineType(types: !1690)
!1690 = !{!1682, !1660}
!1691 = !DISubprogram(name: "back", linkageName: "_ZN6VectorIiE4backEv", scope: !1535, file: !1340, line: 169, type: !1686, scopeLine: 169, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1692 = !DISubprogram(name: "back", linkageName: "_ZNK6VectorIiE4backEv", scope: !1535, file: !1340, line: 170, type: !1689, scopeLine: 170, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1693 = !DISubprogram(name: "unchecked_at", linkageName: "_ZN6VectorIiE12unchecked_atEi", scope: !1535, file: !1340, line: 172, type: !1676, scopeLine: 172, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1694 = !DISubprogram(name: "unchecked_at", linkageName: "_ZNK6VectorIiE12unchecked_atEi", scope: !1535, file: !1340, line: 173, type: !1680, scopeLine: 173, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1695 = !DISubprogram(name: "at_u", linkageName: "_ZN6VectorIiE4at_uEi", scope: !1535, file: !1340, line: 174, type: !1676, scopeLine: 174, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1696 = !DISubprogram(name: "at_u", linkageName: "_ZNK6VectorIiE4at_uEi", scope: !1535, file: !1340, line: 175, type: !1680, scopeLine: 175, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1697 = !DISubprogram(name: "data", linkageName: "_ZN6VectorIiE4dataEv", scope: !1535, file: !1340, line: 177, type: !1698, scopeLine: 177, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1698 = !DISubroutineType(types: !1699)
!1699 = !{!1653, !1618}
!1700 = !DISubprogram(name: "data", linkageName: "_ZNK6VectorIiE4dataEv", scope: !1535, file: !1340, line: 178, type: !1701, scopeLine: 178, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1701 = !DISubroutineType(types: !1702)
!1702 = !{!1659, !1660}
!1703 = !DISubprogram(name: "push_back", linkageName: "_ZN6VectorIiE9push_backEi", scope: !1535, file: !1340, line: 180, type: !1704, scopeLine: 180, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1704 = !DISubroutineType(types: !1705)
!1705 = !{null, !1618, !1622}
!1706 = !DISubprogram(name: "pop_back", linkageName: "_ZN6VectorIiE8pop_backEv", scope: !1535, file: !1340, line: 185, type: !1616, scopeLine: 185, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1707 = !DISubprogram(name: "push_front", linkageName: "_ZN6VectorIiE10push_frontEi", scope: !1535, file: !1340, line: 186, type: !1704, scopeLine: 186, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1708 = !DISubprogram(name: "pop_front", linkageName: "_ZN6VectorIiE9pop_frontEv", scope: !1535, file: !1340, line: 187, type: !1616, scopeLine: 187, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1709 = !DISubprogram(name: "insert", linkageName: "_ZN6VectorIiE6insertEPii", scope: !1535, file: !1340, line: 189, type: !1710, scopeLine: 189, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1710 = !DISubroutineType(types: !1711)
!1711 = !{!1652, !1618, !1652, !1622}
!1712 = !DISubprogram(name: "erase", linkageName: "_ZN6VectorIiE5eraseEPi", scope: !1535, file: !1340, line: 190, type: !1713, scopeLine: 190, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1713 = !DISubroutineType(types: !1714)
!1714 = !{!1652, !1618, !1652}
!1715 = !DISubprogram(name: "erase", linkageName: "_ZN6VectorIiE5eraseEPiS1_", scope: !1535, file: !1340, line: 191, type: !1716, scopeLine: 191, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1716 = !DISubroutineType(types: !1717)
!1717 = !{!1652, !1618, !1652, !1652}
!1718 = !DISubprogram(name: "clear", linkageName: "_ZN6VectorIiE5clearEv", scope: !1535, file: !1340, line: 193, type: !1616, scopeLine: 193, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1719 = !DISubprogram(name: "swap", linkageName: "_ZN6VectorIiE4swapERS0_", scope: !1535, file: !1340, line: 195, type: !1720, scopeLine: 195, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1720 = !DISubroutineType(types: !1721)
!1721 = !{null, !1618, !1642}
!1722 = !{!1628}
!1723 = !DIDerivedType(tag: DW_TAG_member, name: "_slots", scope: !1287, file: !1274, line: 882, baseType: !1724, size: 64, offset: 448)
!1724 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1725, size: 64)
!1725 = !DICompositeType(tag: DW_TAG_structure_type, name: "Slot", scope: !1287, file: !1274, line: 826, flags: DIFlagFwdDecl, identifier: "_ZTSN4Args4SlotE")
!1726 = !DIDerivedType(tag: DW_TAG_member, name: "_simple_slotbuf", scope: !1287, file: !1274, line: 883, baseType: !97, size: 384, offset: 512)
!1727 = !DISubprogram(name: "Args", scope: !1287, file: !1274, line: 254, type: !1728, scopeLine: 254, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1728 = !DISubroutineType(types: !1729)
!1729 = !{null, !1730, !1180}
!1730 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1287, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1731 = !DISubprogram(name: "Args", scope: !1287, file: !1274, line: 259, type: !1732, scopeLine: 259, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1732 = !DISubroutineType(types: !1733)
!1733 = !{null, !1730, !1449, !1180}
!1734 = !DISubprogram(name: "Args", scope: !1287, file: !1274, line: 265, type: !1735, scopeLine: 265, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1735 = !DISubroutineType(types: !1736)
!1736 = !{null, !1730, !1293, !1180}
!1737 = !DISubprogram(name: "Args", scope: !1287, file: !1274, line: 271, type: !1738, scopeLine: 271, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1738 = !DISubroutineType(types: !1739)
!1739 = !{null, !1730, !1449, !1293, !1180}
!1740 = !DISubprogram(name: "Args", scope: !1287, file: !1274, line: 279, type: !1741, scopeLine: 279, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1741 = !DISubroutineType(types: !1742)
!1742 = !{null, !1730, !1743}
!1743 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1744, size: 64)
!1744 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1287)
!1745 = !DISubprogram(name: "~Args", scope: !1287, file: !1274, line: 281, type: !1746, scopeLine: 281, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1746 = !DISubroutineType(types: !1747)
!1747 = !{null, !1730}
!1748 = !DISubprogram(name: "operator=", linkageName: "_ZN4ArgsaSERKS_", scope: !1287, file: !1274, line: 285, type: !1749, scopeLine: 285, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1749 = !DISubroutineType(types: !1750)
!1750 = !{!1751, !1730, !1743}
!1751 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1287, size: 64)
!1752 = !DISubprogram(name: "empty", linkageName: "_ZNK4Args5emptyEv", scope: !1287, file: !1274, line: 289, type: !1753, scopeLine: 289, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1753 = !DISubroutineType(types: !1754)
!1754 = !{!53, !1755}
!1755 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1744, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1756 = !DISubprogram(name: "results_empty", linkageName: "_ZNK4Args13results_emptyEv", scope: !1287, file: !1274, line: 294, type: !1753, scopeLine: 294, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1757 = !DISubprogram(name: "clear", linkageName: "_ZN4Args5clearEv", scope: !1287, file: !1274, line: 301, type: !1758, scopeLine: 301, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1758 = !DISubroutineType(types: !1759)
!1759 = !{!1751, !1730}
!1760 = !DISubprogram(name: "bind", linkageName: "_ZN4Args4bindER6VectorI6StringE", scope: !1287, file: !1274, line: 313, type: !1761, scopeLine: 313, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1761 = !DISubroutineType(types: !1762)
!1762 = !{!1751, !1730, !1458}
!1763 = !DISubprogram(name: "push_back", linkageName: "_ZN4Args9push_backERK6String", scope: !1287, file: !1274, line: 317, type: !1764, scopeLine: 317, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1764 = !DISubroutineType(types: !1765)
!1765 = !{!1751, !1730, !595}
!1766 = !DISubprogram(name: "push_back_words", linkageName: "_ZN4Args15push_back_wordsERK6String", scope: !1287, file: !1274, line: 331, type: !1764, scopeLine: 331, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1767 = !DISubprogram(name: "push_back_args", linkageName: "_ZN4Args14push_back_argsERK6String", scope: !1287, file: !1274, line: 335, type: !1764, scopeLine: 335, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1768 = !DISubprogram(name: "reset", linkageName: "_ZN4Args5resetEv", scope: !1287, file: !1274, line: 350, type: !1758, scopeLine: 350, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1769 = !DISubprogram(name: "status", linkageName: "_ZNK4Args6statusEv", scope: !1287, file: !1274, line: 631, type: !1753, scopeLine: 631, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1770 = !DISubprogram(name: "status", linkageName: "_ZN4Args6statusERb", scope: !1287, file: !1274, line: 636, type: !1771, scopeLine: 636, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1771 = !DISubroutineType(types: !1772)
!1772 = !{!1751, !1730, !1773}
!1773 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !53, size: 64)
!1774 = !DISubprogram(name: "status", linkageName: "_ZNK4Args6statusERb", scope: !1287, file: !1274, line: 641, type: !1775, scopeLine: 641, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1775 = !DISubroutineType(types: !1776)
!1776 = !{!1743, !1755, !1773}
!1777 = !DISubprogram(name: "read_status", linkageName: "_ZNK4Args11read_statusEv", scope: !1287, file: !1274, line: 649, type: !1753, scopeLine: 649, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1778 = !DISubprogram(name: "read_status", linkageName: "_ZN4Args11read_statusERb", scope: !1287, file: !1274, line: 655, type: !1771, scopeLine: 655, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1779 = !DISubprogram(name: "read_status", linkageName: "_ZNK4Args11read_statusERb", scope: !1287, file: !1274, line: 660, type: !1775, scopeLine: 660, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1780 = !DISubprogram(name: "strip", linkageName: "_ZN4Args5stripEv", scope: !1287, file: !1274, line: 667, type: !1758, scopeLine: 667, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1781 = !DISubprogram(name: "execute", linkageName: "_ZN4Args7executeEv", scope: !1287, file: !1274, line: 675, type: !1782, scopeLine: 675, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1782 = !DISubroutineType(types: !1783)
!1783 = !{!34, !1730}
!1784 = !DISubprogram(name: "consume", linkageName: "_ZN4Args7consumeEv", scope: !1287, file: !1274, line: 684, type: !1782, scopeLine: 684, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1785 = !DISubprogram(name: "complete", linkageName: "_ZN4Args8completeEv", scope: !1287, file: !1274, line: 693, type: !1782, scopeLine: 693, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1786 = !DISubprogram(name: "initialize", linkageName: "_ZN4Args10initializeEPK6VectorI6StringE", scope: !1287, file: !1274, line: 885, type: !1787, scopeLine: 885, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1787 = !DISubroutineType(types: !1788)
!1788 = !{null, !1730, !1789}
!1789 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1450, size: 64)
!1790 = !DISubprogram(name: "reset_from", linkageName: "_ZN4Args10reset_fromEi", scope: !1287, file: !1274, line: 886, type: !1791, scopeLine: 886, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1791 = !DISubroutineType(types: !1792)
!1792 = !{null, !1730, !34}
!1793 = !DISubprogram(name: "find", linkageName: "_ZN4Args4findEPKciRPNS_4SlotE", scope: !1287, file: !1274, line: 888, type: !1794, scopeLine: 888, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1794 = !DISubroutineType(types: !1795)
!1795 = !{!554, !1730, !566, !34, !1796}
!1796 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1724, size: 64)
!1797 = !DISubprogram(name: "postparse", linkageName: "_ZN4Args9postparseEbPNS_4SlotE", scope: !1287, file: !1274, line: 889, type: !1798, scopeLine: 889, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1798 = !DISubroutineType(types: !1799)
!1799 = !{null, !1730, !53, !1724}
!1800 = !DISubprogram(name: "check_complete", linkageName: "_ZN4Args14check_completeEv", scope: !1287, file: !1274, line: 890, type: !1746, scopeLine: 890, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1801 = !DISubprogram(name: "simple_slot_size", linkageName: "_ZN4Args16simple_slot_sizeEi", scope: !1287, file: !1274, line: 892, type: !1802, scopeLine: 892, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1802 = !DISubroutineType(types: !1803)
!1803 = !{!34, !34}
!1804 = !DISubprogram(name: "simple_slot_info", linkageName: "_ZN4Args16simple_slot_infoEiiRPvRPS0_", scope: !1287, file: !1274, line: 893, type: !1805, scopeLine: 893, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1805 = !DISubroutineType(types: !1806)
!1806 = !{null, !1730, !34, !34, !1807, !1808}
!1807 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !135, size: 64)
!1808 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1809, size: 64)
!1809 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !135, size: 64)
!1810 = !DISubprogram(name: "simple_slot", linkageName: "_ZN4Args11simple_slotEPvm", scope: !1287, file: !1274, line: 895, type: !1811, scopeLine: 895, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1811 = !DISubroutineType(types: !1812)
!1812 = !{!135, !1730, !135, !133}
!1813 = !DIDerivedType(tag: DW_TAG_typedef, name: "click_int_large_t", file: !1439, line: 200, baseType: !1814)
!1814 = !DIDerivedType(tag: DW_TAG_typedef, name: "click_intmax_t", file: !1439, line: 181, baseType: !640)
!1815 = !DIDerivedType(tag: DW_TAG_typedef, name: "unsigned_v_type", scope: !1816, file: !1274, line: 1064, baseType: !1855)
!1816 = distinct !DISubprogram(name: "parse_saturating<int>", linkageName: "_ZN6IntArg16parse_saturatingIiEEbRK6StringRT_RK10ArgContext", scope: !1817, file: !1274, line: 1053, type: !1838, scopeLine: 1053, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1841, declaration: !1840, retainedNodes: !1843)
!1817 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "IntArg", file: !1274, line: 1040, size: 64, flags: DIFlagTypePassByValue | DIFlagNonTrivial, elements: !1818, identifier: "_ZTS6IntArg")
!1818 = !{!1819, !1820, !1821, !1822, !1826, !1831, !1834}
!1819 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !1817, baseType: !1275, flags: DIFlagPublic, extraData: i32 0)
!1820 = !DIDerivedType(tag: DW_TAG_member, name: "base", scope: !1817, file: !1274, line: 1085, baseType: !34, size: 32, flags: DIFlagPublic)
!1821 = !DIDerivedType(tag: DW_TAG_member, name: "status", scope: !1817, file: !1274, line: 1086, baseType: !34, size: 32, offset: 32, flags: DIFlagPublic)
!1822 = !DISubprogram(name: "IntArg", scope: !1817, file: !1274, line: 1044, type: !1823, scopeLine: 1044, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1823 = !DISubroutineType(types: !1824)
!1824 = !{null, !1825, !34}
!1825 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1817, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1826 = !DISubprogram(name: "parse", linkageName: "_ZN6IntArg5parseEPKcS1_biPji", scope: !1817, file: !1274, line: 1048, type: !1827, scopeLine: 1048, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1827 = !DISubroutineType(types: !1828)
!1828 = !{!566, !1825, !566, !566, !53, !34, !1829, !34}
!1829 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1830, size: 64)
!1830 = !DIDerivedType(tag: DW_TAG_typedef, name: "limb_type", scope: !1817, file: !1274, line: 1042, baseType: !12)
!1831 = !DISubprogram(name: "span", linkageName: "_ZN6IntArg4spanEPKcS1_bRi", scope: !1817, file: !1274, line: 1090, type: !1832, scopeLine: 1090, flags: DIFlagProtected | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1832 = !DISubroutineType(types: !1833)
!1833 = !{!566, !566, !566, !53, !1678}
!1834 = !DISubprogram(name: "range_error", linkageName: "_ZN6IntArg11range_errorERK10ArgContextbx", scope: !1817, file: !1274, line: 1092, type: !1835, scopeLine: 1092, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1835 = !DISubroutineType(types: !1836)
!1836 = !{null, !1825, !1837, !53, !1813}
!1837 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1309, size: 64)
!1838 = !DISubroutineType(types: !1839)
!1839 = !{!53, !1825, !595, !1678, !1837}
!1840 = !DISubprogram(name: "parse_saturating<int>", linkageName: "_ZN6IntArg16parse_saturatingIiEEbRK6StringRT_RK10ArgContext", scope: !1817, file: !1274, line: 1053, type: !1838, scopeLine: 1053, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1841)
!1841 = !{!1842}
!1842 = !DITemplateTypeParameter(name: "V", type: !34)
!1843 = !{!1844, !1846, !1847, !1848, !1849, !1850, !1851}
!1844 = !DILocalVariable(name: "this", arg: 1, scope: !1816, type: !1845, flags: DIFlagArtificial | DIFlagObjectPointer)
!1845 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1817, size: 64)
!1846 = !DILocalVariable(name: "str", arg: 2, scope: !1816, file: !1274, line: 1053, type: !595)
!1847 = !DILocalVariable(name: "result", arg: 3, scope: !1816, file: !1274, line: 1053, type: !1678)
!1848 = !DILocalVariable(name: "args", arg: 4, scope: !1816, file: !1274, line: 1053, type: !1837)
!1849 = !DILocalVariable(name: "is_signed", scope: !1816, file: !1274, line: 1054, type: !1443)
!1850 = !DILocalVariable(name: "nlimb", scope: !1816, file: !1274, line: 1055, type: !1330)
!1851 = !DILocalVariable(name: "x", scope: !1816, file: !1274, line: 1056, type: !1852)
!1852 = !DICompositeType(tag: DW_TAG_array_type, baseType: !1830, size: 32, elements: !1853)
!1853 = !{!1854}
!1854 = !DISubrange(count: 1)
!1855 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1856, file: !1439, line: 461, baseType: !1857)
!1856 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "make_unsigned<int>", file: !1439, line: 460, size: 8, flags: DIFlagTypePassByValue, elements: !452, templateParams: !1722, identifier: "_ZTS13make_unsignedIiE")
!1857 = !DIDerivedType(tag: DW_TAG_typedef, name: "unsigned_type", scope: !1858, file: !1439, line: 345, baseType: !16)
!1858 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "integer_traits<int>", file: !1439, line: 338, size: 8, flags: DIFlagTypePassByValue, elements: !1859, templateParams: !1722, identifier: "_ZTS14integer_traitsIiE")
!1859 = !{!1860, !1861, !1862, !1863, !1864, !1865}
!1860 = !DIDerivedType(tag: DW_TAG_member, name: "is_numeric", scope: !1858, file: !1439, line: 339, baseType: !1443, flags: DIFlagStaticMember, extraData: i1 true)
!1861 = !DIDerivedType(tag: DW_TAG_member, name: "is_integral", scope: !1858, file: !1439, line: 340, baseType: !1443, flags: DIFlagStaticMember, extraData: i1 true)
!1862 = !DIDerivedType(tag: DW_TAG_member, name: "const_min", scope: !1858, file: !1439, line: 341, baseType: !1330, flags: DIFlagStaticMember, extraData: i32 -2147483648)
!1863 = !DIDerivedType(tag: DW_TAG_member, name: "const_max", scope: !1858, file: !1439, line: 342, baseType: !1330, flags: DIFlagStaticMember, extraData: i32 2147483647)
!1864 = !DIDerivedType(tag: DW_TAG_member, name: "is_signed", scope: !1858, file: !1439, line: 343, baseType: !1443, flags: DIFlagStaticMember, extraData: i1 true)
!1865 = !DISubprogram(name: "negative", linkageName: "_ZN14integer_traitsIiE8negativeEi", scope: !1858, file: !1439, line: 348, type: !1866, scopeLine: 348, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1866 = !DISubroutineType(types: !1867)
!1867 = !{!53, !1868}
!1868 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !1858, file: !1439, line: 346, baseType: !34)
!1869 = !{!1870, !1926, !1930, !1934, !1938, !1944, !1946, !1951, !1953, !1958, !1962, !1966, !1975, !1979, !1983, !1987, !1991, !1995, !1999, !2003, !2007, !2011, !2019, !2023, !2027, !2029, !2031, !2035, !2039, !2045, !2049, !2053, !2055, !2063, !2067, !2074, !2076, !2080, !2084, !2088, !2092, !2096, !2101, !2106, !2107, !2108, !2109, !2111, !2112, !2113, !2114, !2115, !2116, !2117, !2119, !2120, !2121, !2122, !2123, !2124, !2125, !2130, !2131, !2132, !2133, !2134, !2135, !2136, !2137, !2138, !2139, !2140, !2141, !2142, !2143, !2144, !2145, !2146, !2147, !2148, !2149, !2150, !2151, !2152, !2153, !2154, !2160, !2162, !2164, !2168, !2170, !2172, !2174, !2176, !2178, !2180, !2182, !2186, !2190, !2192, !2194, !2199, !2201, !2203, !2205, !2207, !2209, !2211, !2214, !2216, !2218, !2222, !2226, !2228, !2230, !2232, !2234, !2236, !2238, !2240, !2242, !2244, !2246, !2250, !2254, !2256, !2258, !2260, !2262, !2264, !2266, !2268, !2270, !2272, !2274, !2276, !2278, !2280, !2282, !2284, !2288, !2292, !2296, !2298, !2300, !2302, !2304, !2306, !2308, !2310, !2312, !2314, !2318, !2322, !2326, !2328, !2330, !2332, !2336, !2340, !2344, !2346, !2348, !2350, !2352, !2354, !2356, !2358, !2360, !2362, !2364, !2366, !2368, !2372, !2376, !2380, !2382, !2384, !2386, !2388, !2392, !2396, !2398, !2400, !2402, !2404, !2406, !2408, !2412, !2416, !2418, !2420, !2422, !2424, !2428, !2432, !2436, !2438, !2440, !2442, !2444, !2446, !2448, !2452, !2456, !2460, !2462, !2466, !2470, !2472, !2474, !2476, !2478, !2480, !2482, !2484}
!1870 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1872, file: !1873, line: 58)
!1871 = !DINamespace(name: "std", scope: null)
!1872 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "exception_ptr", scope: !1874, file: !1873, line: 80, size: 64, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !1875, identifier: "_ZTSNSt15__exception_ptr13exception_ptrE")
!1873 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/bits/exception_ptr.h", directory: "")
!1874 = !DINamespace(name: "__exception_ptr", scope: !1871)
!1875 = !{!1876, !1877, !1881, !1884, !1885, !1890, !1891, !1895, !1901, !1905, !1909, !1912, !1913, !1916, !1919}
!1876 = !DIDerivedType(tag: DW_TAG_member, name: "_M_exception_object", scope: !1872, file: !1873, line: 82, baseType: !135, size: 64)
!1877 = !DISubprogram(name: "exception_ptr", scope: !1872, file: !1873, line: 84, type: !1878, scopeLine: 84, flags: DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1878 = !DISubroutineType(types: !1879)
!1879 = !{null, !1880, !135}
!1880 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1872, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1881 = !DISubprogram(name: "_M_addref", linkageName: "_ZNSt15__exception_ptr13exception_ptr9_M_addrefEv", scope: !1872, file: !1873, line: 86, type: !1882, scopeLine: 86, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1882 = !DISubroutineType(types: !1883)
!1883 = !{null, !1880}
!1884 = !DISubprogram(name: "_M_release", linkageName: "_ZNSt15__exception_ptr13exception_ptr10_M_releaseEv", scope: !1872, file: !1873, line: 87, type: !1882, scopeLine: 87, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1885 = !DISubprogram(name: "_M_get", linkageName: "_ZNKSt15__exception_ptr13exception_ptr6_M_getEv", scope: !1872, file: !1873, line: 89, type: !1886, scopeLine: 89, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1886 = !DISubroutineType(types: !1887)
!1887 = !{!135, !1888}
!1888 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1889, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1889 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1872)
!1890 = !DISubprogram(name: "exception_ptr", scope: !1872, file: !1873, line: 97, type: !1882, scopeLine: 97, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1891 = !DISubprogram(name: "exception_ptr", scope: !1872, file: !1873, line: 99, type: !1892, scopeLine: 99, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1892 = !DISubroutineType(types: !1893)
!1893 = !{null, !1880, !1894}
!1894 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1889, size: 64)
!1895 = !DISubprogram(name: "exception_ptr", scope: !1872, file: !1873, line: 102, type: !1896, scopeLine: 102, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1896 = !DISubroutineType(types: !1897)
!1897 = !{null, !1880, !1898}
!1898 = !DIDerivedType(tag: DW_TAG_typedef, name: "nullptr_t", scope: !1871, file: !1899, line: 264, baseType: !1900)
!1899 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/x86_64-pc-linux-gnu/bits/c++config.h", directory: "")
!1900 = !DIBasicType(tag: DW_TAG_unspecified_type, name: "decltype(nullptr)")
!1901 = !DISubprogram(name: "exception_ptr", scope: !1872, file: !1873, line: 106, type: !1902, scopeLine: 106, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1902 = !DISubroutineType(types: !1903)
!1903 = !{null, !1880, !1904}
!1904 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !1872, size: 64)
!1905 = !DISubprogram(name: "operator=", linkageName: "_ZNSt15__exception_ptr13exception_ptraSERKS0_", scope: !1872, file: !1873, line: 119, type: !1906, scopeLine: 119, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1906 = !DISubroutineType(types: !1907)
!1907 = !{!1908, !1880, !1894}
!1908 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1872, size: 64)
!1909 = !DISubprogram(name: "operator=", linkageName: "_ZNSt15__exception_ptr13exception_ptraSEOS0_", scope: !1872, file: !1873, line: 123, type: !1910, scopeLine: 123, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1910 = !DISubroutineType(types: !1911)
!1911 = !{!1908, !1880, !1904}
!1912 = !DISubprogram(name: "~exception_ptr", scope: !1872, file: !1873, line: 130, type: !1882, scopeLine: 130, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1913 = !DISubprogram(name: "swap", linkageName: "_ZNSt15__exception_ptr13exception_ptr4swapERS0_", scope: !1872, file: !1873, line: 133, type: !1914, scopeLine: 133, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1914 = !DISubroutineType(types: !1915)
!1915 = !{null, !1880, !1908}
!1916 = !DISubprogram(name: "operator bool", linkageName: "_ZNKSt15__exception_ptr13exception_ptrcvbEv", scope: !1872, file: !1873, line: 145, type: !1917, scopeLine: 145, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1917 = !DISubroutineType(types: !1918)
!1918 = !{!53, !1888}
!1919 = !DISubprogram(name: "__cxa_exception_type", linkageName: "_ZNKSt15__exception_ptr13exception_ptr20__cxa_exception_typeEv", scope: !1872, file: !1873, line: 154, type: !1920, scopeLine: 154, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1920 = !DISubroutineType(types: !1921)
!1921 = !{!1922, !1888}
!1922 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1923, size: 64)
!1923 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1924)
!1924 = !DICompositeType(tag: DW_TAG_class_type, name: "type_info", scope: !1871, file: !1925, line: 88, flags: DIFlagFwdDecl, identifier: "_ZTSSt9type_info")
!1925 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/typeinfo", directory: "")
!1926 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1874, entity: !1927, file: !1873, line: 74)
!1927 = !DISubprogram(name: "rethrow_exception", linkageName: "_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE", scope: !1871, file: !1873, line: 70, type: !1928, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1928 = !DISubroutineType(types: !1929)
!1929 = !{null, !1872}
!1930 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1931, file: !1933, line: 52)
!1931 = !DISubprogram(name: "abs", scope: !1932, file: !1932, line: 840, type: !1802, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1932 = !DIFile(filename: "/usr/include/stdlib.h", directory: "")
!1933 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/bits/std_abs.h", directory: "")
!1934 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1935, file: !1937, line: 127)
!1935 = !DIDerivedType(tag: DW_TAG_typedef, name: "div_t", file: !1932, line: 62, baseType: !1936)
!1936 = !DICompositeType(tag: DW_TAG_structure_type, file: !1932, line: 58, flags: DIFlagFwdDecl, identifier: "_ZTS5div_t")
!1937 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/cstdlib", directory: "")
!1938 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1939, file: !1937, line: 128)
!1939 = !DIDerivedType(tag: DW_TAG_typedef, name: "ldiv_t", file: !1932, line: 70, baseType: !1940)
!1940 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !1932, line: 66, size: 128, flags: DIFlagTypePassByValue, elements: !1941, identifier: "_ZTS6ldiv_t")
!1941 = !{!1942, !1943}
!1942 = !DIDerivedType(tag: DW_TAG_member, name: "quot", scope: !1940, file: !1932, line: 68, baseType: !395, size: 64)
!1943 = !DIDerivedType(tag: DW_TAG_member, name: "rem", scope: !1940, file: !1932, line: 69, baseType: !395, size: 64, offset: 64)
!1944 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1945, file: !1937, line: 130)
!1945 = !DISubprogram(name: "abort", scope: !1932, file: !1932, line: 591, type: !236, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1946 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1947, file: !1937, line: 134)
!1947 = !DISubprogram(name: "atexit", scope: !1932, file: !1932, line: 595, type: !1948, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1948 = !DISubroutineType(types: !1949)
!1949 = !{!34, !1950}
!1950 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !236, size: 64)
!1951 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1952, file: !1937, line: 137)
!1952 = !DISubprogram(name: "at_quick_exit", scope: !1932, file: !1932, line: 600, type: !1948, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1953 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1954, file: !1937, line: 140)
!1954 = !DISubprogram(name: "atof", scope: !1955, file: !1955, line: 25, type: !1956, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1955 = !DIFile(filename: "/usr/include/bits/stdlib-float.h", directory: "")
!1956 = !DISubroutineType(types: !1957)
!1957 = !{!415, !566}
!1958 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1959, file: !1937, line: 141)
!1959 = !DISubprogram(name: "atoi", scope: !1932, file: !1932, line: 361, type: !1960, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1960 = !DISubroutineType(types: !1961)
!1961 = !{!34, !566}
!1962 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1963, file: !1937, line: 142)
!1963 = !DISubprogram(name: "atol", scope: !1932, file: !1932, line: 366, type: !1964, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1964 = !DISubroutineType(types: !1965)
!1965 = !{!395, !566}
!1966 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1967, file: !1937, line: 143)
!1967 = !DISubprogram(name: "bsearch", scope: !1968, file: !1968, line: 20, type: !1969, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1968 = !DIFile(filename: "/usr/include/bits/stdlib-bsearch.h", directory: "")
!1969 = !DISubroutineType(types: !1970)
!1970 = !{!135, !224, !224, !133, !133, !1971}
!1971 = !DIDerivedType(tag: DW_TAG_typedef, name: "__compar_fn_t", file: !1932, line: 808, baseType: !1972)
!1972 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1973, size: 64)
!1973 = !DISubroutineType(types: !1974)
!1974 = !{!34, !224, !224}
!1975 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1976, file: !1937, line: 144)
!1976 = !DISubprogram(name: "calloc", scope: !1932, file: !1932, line: 542, type: !1977, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1977 = !DISubroutineType(types: !1978)
!1978 = !{!135, !133, !133}
!1979 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1980, file: !1937, line: 145)
!1980 = !DISubprogram(name: "div", scope: !1932, file: !1932, line: 852, type: !1981, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1981 = !DISubroutineType(types: !1982)
!1982 = !{!1935, !34, !34}
!1983 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1984, file: !1937, line: 146)
!1984 = !DISubprogram(name: "exit", scope: !1932, file: !1932, line: 617, type: !1985, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1985 = !DISubroutineType(types: !1986)
!1986 = !{null, !34}
!1987 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1988, file: !1937, line: 147)
!1988 = !DISubprogram(name: "free", scope: !1932, file: !1932, line: 565, type: !1989, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1989 = !DISubroutineType(types: !1990)
!1990 = !{null, !135}
!1991 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1992, file: !1937, line: 148)
!1992 = !DISubprogram(name: "getenv", scope: !1932, file: !1932, line: 634, type: !1993, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1993 = !DISubroutineType(types: !1994)
!1994 = !{!778, !566}
!1995 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !1996, file: !1937, line: 149)
!1996 = !DISubprogram(name: "labs", scope: !1932, file: !1932, line: 841, type: !1997, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1997 = !DISubroutineType(types: !1998)
!1998 = !{!395, !395}
!1999 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2000, file: !1937, line: 150)
!2000 = !DISubprogram(name: "ldiv", scope: !1932, file: !1932, line: 854, type: !2001, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2001 = !DISubroutineType(types: !2002)
!2002 = !{!1939, !395, !395}
!2003 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2004, file: !1937, line: 151)
!2004 = !DISubprogram(name: "malloc", scope: !1932, file: !1932, line: 539, type: !2005, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2005 = !DISubroutineType(types: !2006)
!2006 = !{!135, !133}
!2007 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2008, file: !1937, line: 153)
!2008 = !DISubprogram(name: "mblen", scope: !1932, file: !1932, line: 922, type: !2009, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2009 = !DISubroutineType(types: !2010)
!2010 = !{!34, !566, !133}
!2011 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2012, file: !1937, line: 154)
!2012 = !DISubprogram(name: "mbstowcs", scope: !1932, file: !1932, line: 933, type: !2013, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2013 = !DISubroutineType(types: !2014)
!2014 = !{!133, !2015, !2018, !133}
!2015 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !2016)
!2016 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2017, size: 64)
!2017 = !DIBasicType(name: "wchar_t", size: 32, encoding: DW_ATE_signed)
!2018 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !566)
!2019 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2020, file: !1937, line: 155)
!2020 = !DISubprogram(name: "mbtowc", scope: !1932, file: !1932, line: 925, type: !2021, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2021 = !DISubroutineType(types: !2022)
!2022 = !{!34, !2015, !2018, !133}
!2023 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2024, file: !1937, line: 157)
!2024 = !DISubprogram(name: "qsort", scope: !1932, file: !1932, line: 830, type: !2025, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2025 = !DISubroutineType(types: !2026)
!2026 = !{null, !135, !133, !133, !1971}
!2027 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2028, file: !1937, line: 160)
!2028 = !DISubprogram(name: "quick_exit", scope: !1932, file: !1932, line: 623, type: !1985, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!2029 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2030, file: !1937, line: 163)
!2030 = !DISubprogram(name: "rand", scope: !1932, file: !1932, line: 453, type: !800, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2031 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2032, file: !1937, line: 164)
!2032 = !DISubprogram(name: "realloc", scope: !1932, file: !1932, line: 550, type: !2033, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2033 = !DISubroutineType(types: !2034)
!2034 = !{!135, !135, !133}
!2035 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2036, file: !1937, line: 165)
!2036 = !DISubprogram(name: "srand", scope: !1932, file: !1932, line: 455, type: !2037, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2037 = !DISubroutineType(types: !2038)
!2038 = !{null, !16}
!2039 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2040, file: !1937, line: 166)
!2040 = !DISubprogram(name: "strtod", scope: !1932, file: !1932, line: 117, type: !2041, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2041 = !DISubroutineType(types: !2042)
!2042 = !{!415, !2018, !2043}
!2043 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !2044)
!2044 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !778, size: 64)
!2045 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2046, file: !1937, line: 167)
!2046 = !DISubprogram(name: "strtol", scope: !1932, file: !1932, line: 176, type: !2047, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2047 = !DISubroutineType(types: !2048)
!2048 = !{!395, !2018, !2043, !34}
!2049 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2050, file: !1937, line: 168)
!2050 = !DISubprogram(name: "strtoul", scope: !1932, file: !1932, line: 180, type: !2051, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2051 = !DISubroutineType(types: !2052)
!2052 = !{!115, !2018, !2043, !34}
!2053 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2054, file: !1937, line: 169)
!2054 = !DISubprogram(name: "system", scope: !1932, file: !1932, line: 784, type: !1960, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2055 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2056, file: !1937, line: 171)
!2056 = !DISubprogram(name: "wcstombs", scope: !1932, file: !1932, line: 936, type: !2057, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2057 = !DISubroutineType(types: !2058)
!2058 = !{!133, !2059, !2060, !133}
!2059 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !778)
!2060 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !2061)
!2061 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2062, size: 64)
!2062 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !2017)
!2063 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2064, file: !1937, line: 172)
!2064 = !DISubprogram(name: "wctomb", scope: !1932, file: !1932, line: 929, type: !2065, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2065 = !DISubroutineType(types: !2066)
!2066 = !{!34, !778, !2017}
!2067 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2069, file: !1937, line: 200)
!2068 = !DINamespace(name: "__gnu_cxx", scope: null)
!2069 = !DIDerivedType(tag: DW_TAG_typedef, name: "lldiv_t", file: !1932, line: 80, baseType: !2070)
!2070 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !1932, line: 76, size: 128, flags: DIFlagTypePassByValue, elements: !2071, identifier: "_ZTS7lldiv_t")
!2071 = !{!2072, !2073}
!2072 = !DIDerivedType(tag: DW_TAG_member, name: "quot", scope: !2070, file: !1932, line: 78, baseType: !640, size: 64)
!2073 = !DIDerivedType(tag: DW_TAG_member, name: "rem", scope: !2070, file: !1932, line: 79, baseType: !640, size: 64, offset: 64)
!2074 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2075, file: !1937, line: 206)
!2075 = !DISubprogram(name: "_Exit", scope: !1932, file: !1932, line: 629, type: !1985, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!2076 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2077, file: !1937, line: 210)
!2077 = !DISubprogram(name: "llabs", scope: !1932, file: !1932, line: 844, type: !2078, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2078 = !DISubroutineType(types: !2079)
!2079 = !{!640, !640}
!2080 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2081, file: !1937, line: 216)
!2081 = !DISubprogram(name: "lldiv", scope: !1932, file: !1932, line: 858, type: !2082, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2082 = !DISubroutineType(types: !2083)
!2083 = !{!2069, !640, !640}
!2084 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2085, file: !1937, line: 227)
!2085 = !DISubprogram(name: "atoll", scope: !1932, file: !1932, line: 373, type: !2086, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2086 = !DISubroutineType(types: !2087)
!2087 = !{!640, !566}
!2088 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2089, file: !1937, line: 228)
!2089 = !DISubprogram(name: "strtoll", scope: !1932, file: !1932, line: 200, type: !2090, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2090 = !DISubroutineType(types: !2091)
!2091 = !{!640, !2018, !2043, !34}
!2092 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2093, file: !1937, line: 229)
!2093 = !DISubprogram(name: "strtoull", scope: !1932, file: !1932, line: 205, type: !2094, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2094 = !DISubroutineType(types: !2095)
!2095 = !{!644, !2018, !2043, !34}
!2096 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2097, file: !1937, line: 231)
!2097 = !DISubprogram(name: "strtof", scope: !1932, file: !1932, line: 123, type: !2098, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2098 = !DISubroutineType(types: !2099)
!2099 = !{!2100, !2018, !2043}
!2100 = !DIBasicType(name: "float", size: 32, encoding: DW_ATE_float)
!2101 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !2068, entity: !2102, file: !1937, line: 232)
!2102 = !DISubprogram(name: "strtold", scope: !1932, file: !1932, line: 126, type: !2103, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2103 = !DISubroutineType(types: !2104)
!2104 = !{!2105, !2018, !2043}
!2105 = !DIBasicType(name: "long double", size: 128, encoding: DW_ATE_float)
!2106 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2069, file: !1937, line: 240)
!2107 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2075, file: !1937, line: 242)
!2108 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2077, file: !1937, line: 244)
!2109 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2110, file: !1937, line: 245)
!2110 = !DISubprogram(name: "div", linkageName: "_ZN9__gnu_cxx3divExx", scope: !2068, file: !1937, line: 213, type: !2082, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2111 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2081, file: !1937, line: 246)
!2112 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2085, file: !1937, line: 248)
!2113 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2097, file: !1937, line: 249)
!2114 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2089, file: !1937, line: 250)
!2115 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2093, file: !1937, line: 251)
!2116 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2102, file: !1937, line: 252)
!2117 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1945, file: !2118, line: 38)
!2118 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/stdlib.h", directory: "")
!2119 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1947, file: !2118, line: 39)
!2120 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1984, file: !2118, line: 40)
!2121 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1952, file: !2118, line: 43)
!2122 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2028, file: !2118, line: 46)
!2123 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1935, file: !2118, line: 51)
!2124 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1939, file: !2118, line: 52)
!2125 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2126, file: !2118, line: 54)
!2126 = !DISubprogram(name: "abs", linkageName: "_ZSt3absg", scope: !1871, file: !1933, line: 103, type: !2127, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2127 = !DISubroutineType(types: !2128)
!2128 = !{!2129, !2129}
!2129 = !DIBasicType(name: "__float128", size: 128, encoding: DW_ATE_float)
!2130 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1954, file: !2118, line: 55)
!2131 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1959, file: !2118, line: 56)
!2132 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1963, file: !2118, line: 57)
!2133 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1967, file: !2118, line: 58)
!2134 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1976, file: !2118, line: 59)
!2135 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2110, file: !2118, line: 60)
!2136 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1988, file: !2118, line: 61)
!2137 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1992, file: !2118, line: 62)
!2138 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !1996, file: !2118, line: 63)
!2139 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2000, file: !2118, line: 64)
!2140 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2004, file: !2118, line: 65)
!2141 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2008, file: !2118, line: 67)
!2142 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2012, file: !2118, line: 68)
!2143 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2020, file: !2118, line: 69)
!2144 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2024, file: !2118, line: 71)
!2145 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2030, file: !2118, line: 72)
!2146 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2032, file: !2118, line: 73)
!2147 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2036, file: !2118, line: 74)
!2148 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2040, file: !2118, line: 75)
!2149 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2046, file: !2118, line: 76)
!2150 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2050, file: !2118, line: 77)
!2151 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2054, file: !2118, line: 78)
!2152 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2056, file: !2118, line: 80)
!2153 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2064, file: !2118, line: 81)
!2154 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2155, file: !2159, line: 83)
!2155 = !DISubprogram(name: "acos", scope: !2156, file: !2156, line: 53, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2156 = !DIFile(filename: "/usr/include/bits/mathcalls.h", directory: "")
!2157 = !DISubroutineType(types: !2158)
!2158 = !{!415, !415}
!2159 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/cmath", directory: "")
!2160 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2161, file: !2159, line: 102)
!2161 = !DISubprogram(name: "asin", scope: !2156, file: !2156, line: 55, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2162 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2163, file: !2159, line: 121)
!2163 = !DISubprogram(name: "atan", scope: !2156, file: !2156, line: 57, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2164 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2165, file: !2159, line: 140)
!2165 = !DISubprogram(name: "atan2", scope: !2156, file: !2156, line: 59, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2166 = !DISubroutineType(types: !2167)
!2167 = !{!415, !415, !415}
!2168 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2169, file: !2159, line: 161)
!2169 = !DISubprogram(name: "ceil", scope: !2156, file: !2156, line: 159, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2170 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2171, file: !2159, line: 180)
!2171 = !DISubprogram(name: "cos", scope: !2156, file: !2156, line: 62, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2172 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2173, file: !2159, line: 199)
!2173 = !DISubprogram(name: "cosh", scope: !2156, file: !2156, line: 71, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2174 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2175, file: !2159, line: 218)
!2175 = !DISubprogram(name: "exp", scope: !2156, file: !2156, line: 95, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2176 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2177, file: !2159, line: 237)
!2177 = !DISubprogram(name: "fabs", scope: !2156, file: !2156, line: 162, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2178 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2179, file: !2159, line: 256)
!2179 = !DISubprogram(name: "floor", scope: !2156, file: !2156, line: 165, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2180 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2181, file: !2159, line: 275)
!2181 = !DISubprogram(name: "fmod", scope: !2156, file: !2156, line: 168, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2182 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2183, file: !2159, line: 296)
!2183 = !DISubprogram(name: "frexp", scope: !2156, file: !2156, line: 98, type: !2184, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2184 = !DISubroutineType(types: !2185)
!2185 = !{!415, !415, !1653}
!2186 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2187, file: !2159, line: 315)
!2187 = !DISubprogram(name: "ldexp", scope: !2156, file: !2156, line: 101, type: !2188, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2188 = !DISubroutineType(types: !2189)
!2189 = !{!415, !415, !34}
!2190 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2191, file: !2159, line: 334)
!2191 = !DISubprogram(name: "log", scope: !2156, file: !2156, line: 104, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2192 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2193, file: !2159, line: 353)
!2193 = !DISubprogram(name: "log10", scope: !2156, file: !2156, line: 107, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2194 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2195, file: !2159, line: 372)
!2195 = !DISubprogram(name: "modf", scope: !2156, file: !2156, line: 110, type: !2196, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2196 = !DISubroutineType(types: !2197)
!2197 = !{!415, !415, !2198}
!2198 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !415, size: 64)
!2199 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2200, file: !2159, line: 384)
!2200 = !DISubprogram(name: "pow", scope: !2156, file: !2156, line: 140, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2201 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2202, file: !2159, line: 421)
!2202 = !DISubprogram(name: "sin", scope: !2156, file: !2156, line: 64, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2203 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2204, file: !2159, line: 440)
!2204 = !DISubprogram(name: "sinh", scope: !2156, file: !2156, line: 73, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2205 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2206, file: !2159, line: 459)
!2206 = !DISubprogram(name: "sqrt", scope: !2156, file: !2156, line: 143, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2207 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2208, file: !2159, line: 478)
!2208 = !DISubprogram(name: "tan", scope: !2156, file: !2156, line: 66, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2209 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2210, file: !2159, line: 497)
!2210 = !DISubprogram(name: "tanh", scope: !2156, file: !2156, line: 75, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2211 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2212, file: !2159, line: 1065)
!2212 = !DIDerivedType(tag: DW_TAG_typedef, name: "double_t", file: !2213, line: 150, baseType: !415)
!2213 = !DIFile(filename: "/usr/include/math.h", directory: "")
!2214 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2215, file: !2159, line: 1066)
!2215 = !DIDerivedType(tag: DW_TAG_typedef, name: "float_t", file: !2213, line: 149, baseType: !2100)
!2216 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2217, file: !2159, line: 1069)
!2217 = !DISubprogram(name: "acosh", scope: !2156, file: !2156, line: 85, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2218 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2219, file: !2159, line: 1070)
!2219 = !DISubprogram(name: "acoshf", scope: !2156, file: !2156, line: 85, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2220 = !DISubroutineType(types: !2221)
!2221 = !{!2100, !2100}
!2222 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2223, file: !2159, line: 1071)
!2223 = !DISubprogram(name: "acoshl", scope: !2156, file: !2156, line: 85, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2224 = !DISubroutineType(types: !2225)
!2225 = !{!2105, !2105}
!2226 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2227, file: !2159, line: 1073)
!2227 = !DISubprogram(name: "asinh", scope: !2156, file: !2156, line: 87, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2228 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2229, file: !2159, line: 1074)
!2229 = !DISubprogram(name: "asinhf", scope: !2156, file: !2156, line: 87, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2230 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2231, file: !2159, line: 1075)
!2231 = !DISubprogram(name: "asinhl", scope: !2156, file: !2156, line: 87, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2232 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2233, file: !2159, line: 1077)
!2233 = !DISubprogram(name: "atanh", scope: !2156, file: !2156, line: 89, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2234 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2235, file: !2159, line: 1078)
!2235 = !DISubprogram(name: "atanhf", scope: !2156, file: !2156, line: 89, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2236 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2237, file: !2159, line: 1079)
!2237 = !DISubprogram(name: "atanhl", scope: !2156, file: !2156, line: 89, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2238 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2239, file: !2159, line: 1081)
!2239 = !DISubprogram(name: "cbrt", scope: !2156, file: !2156, line: 152, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2240 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2241, file: !2159, line: 1082)
!2241 = !DISubprogram(name: "cbrtf", scope: !2156, file: !2156, line: 152, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2242 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2243, file: !2159, line: 1083)
!2243 = !DISubprogram(name: "cbrtl", scope: !2156, file: !2156, line: 152, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2244 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2245, file: !2159, line: 1085)
!2245 = !DISubprogram(name: "copysign", scope: !2156, file: !2156, line: 196, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2246 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2247, file: !2159, line: 1086)
!2247 = !DISubprogram(name: "copysignf", scope: !2156, file: !2156, line: 196, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2248 = !DISubroutineType(types: !2249)
!2249 = !{!2100, !2100, !2100}
!2250 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2251, file: !2159, line: 1087)
!2251 = !DISubprogram(name: "copysignl", scope: !2156, file: !2156, line: 196, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2252 = !DISubroutineType(types: !2253)
!2253 = !{!2105, !2105, !2105}
!2254 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2255, file: !2159, line: 1089)
!2255 = !DISubprogram(name: "erf", scope: !2156, file: !2156, line: 228, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2256 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2257, file: !2159, line: 1090)
!2257 = !DISubprogram(name: "erff", scope: !2156, file: !2156, line: 228, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2258 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2259, file: !2159, line: 1091)
!2259 = !DISubprogram(name: "erfl", scope: !2156, file: !2156, line: 228, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2260 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2261, file: !2159, line: 1093)
!2261 = !DISubprogram(name: "erfc", scope: !2156, file: !2156, line: 229, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2262 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2263, file: !2159, line: 1094)
!2263 = !DISubprogram(name: "erfcf", scope: !2156, file: !2156, line: 229, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2264 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2265, file: !2159, line: 1095)
!2265 = !DISubprogram(name: "erfcl", scope: !2156, file: !2156, line: 229, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2266 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2267, file: !2159, line: 1097)
!2267 = !DISubprogram(name: "exp2", scope: !2156, file: !2156, line: 130, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2268 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2269, file: !2159, line: 1098)
!2269 = !DISubprogram(name: "exp2f", scope: !2156, file: !2156, line: 130, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2270 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2271, file: !2159, line: 1099)
!2271 = !DISubprogram(name: "exp2l", scope: !2156, file: !2156, line: 130, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2272 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2273, file: !2159, line: 1101)
!2273 = !DISubprogram(name: "expm1", scope: !2156, file: !2156, line: 119, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2274 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2275, file: !2159, line: 1102)
!2275 = !DISubprogram(name: "expm1f", scope: !2156, file: !2156, line: 119, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2276 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2277, file: !2159, line: 1103)
!2277 = !DISubprogram(name: "expm1l", scope: !2156, file: !2156, line: 119, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2278 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2279, file: !2159, line: 1105)
!2279 = !DISubprogram(name: "fdim", scope: !2156, file: !2156, line: 326, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2280 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2281, file: !2159, line: 1106)
!2281 = !DISubprogram(name: "fdimf", scope: !2156, file: !2156, line: 326, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2282 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2283, file: !2159, line: 1107)
!2283 = !DISubprogram(name: "fdiml", scope: !2156, file: !2156, line: 326, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2284 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2285, file: !2159, line: 1109)
!2285 = !DISubprogram(name: "fma", scope: !2156, file: !2156, line: 335, type: !2286, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2286 = !DISubroutineType(types: !2287)
!2287 = !{!415, !415, !415, !415}
!2288 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2289, file: !2159, line: 1110)
!2289 = !DISubprogram(name: "fmaf", scope: !2156, file: !2156, line: 335, type: !2290, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2290 = !DISubroutineType(types: !2291)
!2291 = !{!2100, !2100, !2100, !2100}
!2292 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2293, file: !2159, line: 1111)
!2293 = !DISubprogram(name: "fmal", scope: !2156, file: !2156, line: 335, type: !2294, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2294 = !DISubroutineType(types: !2295)
!2295 = !{!2105, !2105, !2105, !2105}
!2296 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2297, file: !2159, line: 1113)
!2297 = !DISubprogram(name: "fmax", scope: !2156, file: !2156, line: 329, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2298 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2299, file: !2159, line: 1114)
!2299 = !DISubprogram(name: "fmaxf", scope: !2156, file: !2156, line: 329, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2300 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2301, file: !2159, line: 1115)
!2301 = !DISubprogram(name: "fmaxl", scope: !2156, file: !2156, line: 329, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2302 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2303, file: !2159, line: 1117)
!2303 = !DISubprogram(name: "fmin", scope: !2156, file: !2156, line: 332, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2304 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2305, file: !2159, line: 1118)
!2305 = !DISubprogram(name: "fminf", scope: !2156, file: !2156, line: 332, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2306 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2307, file: !2159, line: 1119)
!2307 = !DISubprogram(name: "fminl", scope: !2156, file: !2156, line: 332, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2308 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2309, file: !2159, line: 1121)
!2309 = !DISubprogram(name: "hypot", scope: !2156, file: !2156, line: 147, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2310 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2311, file: !2159, line: 1122)
!2311 = !DISubprogram(name: "hypotf", scope: !2156, file: !2156, line: 147, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2312 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2313, file: !2159, line: 1123)
!2313 = !DISubprogram(name: "hypotl", scope: !2156, file: !2156, line: 147, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2314 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2315, file: !2159, line: 1125)
!2315 = !DISubprogram(name: "ilogb", scope: !2156, file: !2156, line: 280, type: !2316, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2316 = !DISubroutineType(types: !2317)
!2317 = !{!34, !415}
!2318 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2319, file: !2159, line: 1126)
!2319 = !DISubprogram(name: "ilogbf", scope: !2156, file: !2156, line: 280, type: !2320, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2320 = !DISubroutineType(types: !2321)
!2321 = !{!34, !2100}
!2322 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2323, file: !2159, line: 1127)
!2323 = !DISubprogram(name: "ilogbl", scope: !2156, file: !2156, line: 280, type: !2324, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2324 = !DISubroutineType(types: !2325)
!2325 = !{!34, !2105}
!2326 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2327, file: !2159, line: 1129)
!2327 = !DISubprogram(name: "lgamma", scope: !2156, file: !2156, line: 230, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2328 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2329, file: !2159, line: 1130)
!2329 = !DISubprogram(name: "lgammaf", scope: !2156, file: !2156, line: 230, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2330 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2331, file: !2159, line: 1131)
!2331 = !DISubprogram(name: "lgammal", scope: !2156, file: !2156, line: 230, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2332 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2333, file: !2159, line: 1134)
!2333 = !DISubprogram(name: "llrint", scope: !2156, file: !2156, line: 316, type: !2334, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2334 = !DISubroutineType(types: !2335)
!2335 = !{!640, !415}
!2336 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2337, file: !2159, line: 1135)
!2337 = !DISubprogram(name: "llrintf", scope: !2156, file: !2156, line: 316, type: !2338, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2338 = !DISubroutineType(types: !2339)
!2339 = !{!640, !2100}
!2340 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2341, file: !2159, line: 1136)
!2341 = !DISubprogram(name: "llrintl", scope: !2156, file: !2156, line: 316, type: !2342, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2342 = !DISubroutineType(types: !2343)
!2343 = !{!640, !2105}
!2344 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2345, file: !2159, line: 1138)
!2345 = !DISubprogram(name: "llround", scope: !2156, file: !2156, line: 322, type: !2334, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2346 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2347, file: !2159, line: 1139)
!2347 = !DISubprogram(name: "llroundf", scope: !2156, file: !2156, line: 322, type: !2338, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2348 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2349, file: !2159, line: 1140)
!2349 = !DISubprogram(name: "llroundl", scope: !2156, file: !2156, line: 322, type: !2342, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2350 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2351, file: !2159, line: 1143)
!2351 = !DISubprogram(name: "log1p", scope: !2156, file: !2156, line: 122, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2352 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2353, file: !2159, line: 1144)
!2353 = !DISubprogram(name: "log1pf", scope: !2156, file: !2156, line: 122, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2354 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2355, file: !2159, line: 1145)
!2355 = !DISubprogram(name: "log1pl", scope: !2156, file: !2156, line: 122, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2356 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2357, file: !2159, line: 1147)
!2357 = !DISubprogram(name: "log2", scope: !2156, file: !2156, line: 133, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2358 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2359, file: !2159, line: 1148)
!2359 = !DISubprogram(name: "log2f", scope: !2156, file: !2156, line: 133, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2360 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2361, file: !2159, line: 1149)
!2361 = !DISubprogram(name: "log2l", scope: !2156, file: !2156, line: 133, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2362 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2363, file: !2159, line: 1151)
!2363 = !DISubprogram(name: "logb", scope: !2156, file: !2156, line: 125, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2364 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2365, file: !2159, line: 1152)
!2365 = !DISubprogram(name: "logbf", scope: !2156, file: !2156, line: 125, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2366 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2367, file: !2159, line: 1153)
!2367 = !DISubprogram(name: "logbl", scope: !2156, file: !2156, line: 125, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2368 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2369, file: !2159, line: 1155)
!2369 = !DISubprogram(name: "lrint", scope: !2156, file: !2156, line: 314, type: !2370, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2370 = !DISubroutineType(types: !2371)
!2371 = !{!395, !415}
!2372 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2373, file: !2159, line: 1156)
!2373 = !DISubprogram(name: "lrintf", scope: !2156, file: !2156, line: 314, type: !2374, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2374 = !DISubroutineType(types: !2375)
!2375 = !{!395, !2100}
!2376 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2377, file: !2159, line: 1157)
!2377 = !DISubprogram(name: "lrintl", scope: !2156, file: !2156, line: 314, type: !2378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2378 = !DISubroutineType(types: !2379)
!2379 = !{!395, !2105}
!2380 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2381, file: !2159, line: 1159)
!2381 = !DISubprogram(name: "lround", scope: !2156, file: !2156, line: 320, type: !2370, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2382 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2383, file: !2159, line: 1160)
!2383 = !DISubprogram(name: "lroundf", scope: !2156, file: !2156, line: 320, type: !2374, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2384 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2385, file: !2159, line: 1161)
!2385 = !DISubprogram(name: "lroundl", scope: !2156, file: !2156, line: 320, type: !2378, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2386 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2387, file: !2159, line: 1163)
!2387 = !DISubprogram(name: "nan", scope: !2156, file: !2156, line: 201, type: !1956, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2388 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2389, file: !2159, line: 1164)
!2389 = !DISubprogram(name: "nanf", scope: !2156, file: !2156, line: 201, type: !2390, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2390 = !DISubroutineType(types: !2391)
!2391 = !{!2100, !566}
!2392 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2393, file: !2159, line: 1165)
!2393 = !DISubprogram(name: "nanl", scope: !2156, file: !2156, line: 201, type: !2394, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2394 = !DISubroutineType(types: !2395)
!2395 = !{!2105, !566}
!2396 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2397, file: !2159, line: 1167)
!2397 = !DISubprogram(name: "nearbyint", scope: !2156, file: !2156, line: 294, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2398 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2399, file: !2159, line: 1168)
!2399 = !DISubprogram(name: "nearbyintf", scope: !2156, file: !2156, line: 294, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2400 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2401, file: !2159, line: 1169)
!2401 = !DISubprogram(name: "nearbyintl", scope: !2156, file: !2156, line: 294, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2402 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2403, file: !2159, line: 1171)
!2403 = !DISubprogram(name: "nextafter", scope: !2156, file: !2156, line: 259, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2404 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2405, file: !2159, line: 1172)
!2405 = !DISubprogram(name: "nextafterf", scope: !2156, file: !2156, line: 259, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2406 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2407, file: !2159, line: 1173)
!2407 = !DISubprogram(name: "nextafterl", scope: !2156, file: !2156, line: 259, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2408 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2409, file: !2159, line: 1175)
!2409 = !DISubprogram(name: "nexttoward", scope: !2156, file: !2156, line: 261, type: !2410, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2410 = !DISubroutineType(types: !2411)
!2411 = !{!415, !415, !2105}
!2412 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2413, file: !2159, line: 1176)
!2413 = !DISubprogram(name: "nexttowardf", scope: !2156, file: !2156, line: 261, type: !2414, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2414 = !DISubroutineType(types: !2415)
!2415 = !{!2100, !2100, !2105}
!2416 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2417, file: !2159, line: 1177)
!2417 = !DISubprogram(name: "nexttowardl", scope: !2156, file: !2156, line: 261, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2418 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2419, file: !2159, line: 1179)
!2419 = !DISubprogram(name: "remainder", scope: !2156, file: !2156, line: 272, type: !2166, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2420 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2421, file: !2159, line: 1180)
!2421 = !DISubprogram(name: "remainderf", scope: !2156, file: !2156, line: 272, type: !2248, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2422 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2423, file: !2159, line: 1181)
!2423 = !DISubprogram(name: "remainderl", scope: !2156, file: !2156, line: 272, type: !2252, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2424 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2425, file: !2159, line: 1183)
!2425 = !DISubprogram(name: "remquo", scope: !2156, file: !2156, line: 307, type: !2426, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2426 = !DISubroutineType(types: !2427)
!2427 = !{!415, !415, !415, !1653}
!2428 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2429, file: !2159, line: 1184)
!2429 = !DISubprogram(name: "remquof", scope: !2156, file: !2156, line: 307, type: !2430, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2430 = !DISubroutineType(types: !2431)
!2431 = !{!2100, !2100, !2100, !1653}
!2432 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2433, file: !2159, line: 1185)
!2433 = !DISubprogram(name: "remquol", scope: !2156, file: !2156, line: 307, type: !2434, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2434 = !DISubroutineType(types: !2435)
!2435 = !{!2105, !2105, !2105, !1653}
!2436 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2437, file: !2159, line: 1187)
!2437 = !DISubprogram(name: "rint", scope: !2156, file: !2156, line: 256, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2438 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2439, file: !2159, line: 1188)
!2439 = !DISubprogram(name: "rintf", scope: !2156, file: !2156, line: 256, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2440 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2441, file: !2159, line: 1189)
!2441 = !DISubprogram(name: "rintl", scope: !2156, file: !2156, line: 256, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2442 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2443, file: !2159, line: 1191)
!2443 = !DISubprogram(name: "round", scope: !2156, file: !2156, line: 298, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2444 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2445, file: !2159, line: 1192)
!2445 = !DISubprogram(name: "roundf", scope: !2156, file: !2156, line: 298, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2446 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2447, file: !2159, line: 1193)
!2447 = !DISubprogram(name: "roundl", scope: !2156, file: !2156, line: 298, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2448 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2449, file: !2159, line: 1195)
!2449 = !DISubprogram(name: "scalbln", scope: !2156, file: !2156, line: 290, type: !2450, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2450 = !DISubroutineType(types: !2451)
!2451 = !{!415, !415, !395}
!2452 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2453, file: !2159, line: 1196)
!2453 = !DISubprogram(name: "scalblnf", scope: !2156, file: !2156, line: 290, type: !2454, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2454 = !DISubroutineType(types: !2455)
!2455 = !{!2100, !2100, !395}
!2456 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2457, file: !2159, line: 1197)
!2457 = !DISubprogram(name: "scalblnl", scope: !2156, file: !2156, line: 290, type: !2458, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2458 = !DISubroutineType(types: !2459)
!2459 = !{!2105, !2105, !395}
!2460 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2461, file: !2159, line: 1199)
!2461 = !DISubprogram(name: "scalbn", scope: !2156, file: !2156, line: 276, type: !2188, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2462 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2463, file: !2159, line: 1200)
!2463 = !DISubprogram(name: "scalbnf", scope: !2156, file: !2156, line: 276, type: !2464, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2464 = !DISubroutineType(types: !2465)
!2465 = !{!2100, !2100, !34}
!2466 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2467, file: !2159, line: 1201)
!2467 = !DISubprogram(name: "scalbnl", scope: !2156, file: !2156, line: 276, type: !2468, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2468 = !DISubroutineType(types: !2469)
!2469 = !{!2105, !2105, !34}
!2470 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2471, file: !2159, line: 1203)
!2471 = !DISubprogram(name: "tgamma", scope: !2156, file: !2156, line: 235, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2472 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2473, file: !2159, line: 1204)
!2473 = !DISubprogram(name: "tgammaf", scope: !2156, file: !2156, line: 235, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2474 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2475, file: !2159, line: 1205)
!2475 = !DISubprogram(name: "tgammal", scope: !2156, file: !2156, line: 235, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2476 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2477, file: !2159, line: 1207)
!2477 = !DISubprogram(name: "trunc", scope: !2156, file: !2156, line: 302, type: !2157, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2478 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2479, file: !2159, line: 1208)
!2479 = !DISubprogram(name: "truncf", scope: !2156, file: !2156, line: 302, type: !2220, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2480 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !1871, entity: !2481, file: !2159, line: 1209)
!2481 = !DISubprogram(name: "truncl", scope: !2156, file: !2156, line: 302, type: !2224, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2482 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2126, file: !2483, line: 38)
!2483 = !DIFile(filename: "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.1.0/../../../../include/c++/10.1.0/math.h", directory: "")
!2484 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !0, entity: !2485, file: !2483, line: 54)
!2485 = !DISubprogram(name: "modf", linkageName: "_ZSt4modfePe", scope: !1871, file: !2159, line: 380, type: !2486, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2486 = !DISubroutineType(types: !2487)
!2487 = !{!2105, !2105, !2488}
!2488 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2105, size: 64)
!2489 = !{i32 7, !"Dwarf Version", i32 4}
!2490 = !{i32 2, !"Debug Info Version", i32 3}
!2491 = !{i32 1, !"wchar_size", i32 4}
!2492 = !{i32 7, !"PIC Level", i32 2}
!2493 = !{i32 7, !"PIE Level", i32 2}
!2494 = !{!"clang version 10.0.0 "}
!2495 = distinct !DISubprogram(name: "Resize", linkageName: "_ZN6ResizeC2Ev", scope: !2496, file: !1, line: 13, type: !2503, scopeLine: 14, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2502, retainedNodes: !2523)
!2496 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "Resize", file: !2497, line: 25, size: 960, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !2498, vtableHolder: !1176)
!2497 = !DIFile(filename: "../elements/standard/resize.hh", directory: "/home/john/projects/click/ir-dir")
!2498 = !{!2499, !2500, !2501, !2502, !2506, !2511, !2512, !2513, !2514, !2517, !2520}
!2499 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !2496, baseType: !1176, flags: DIFlagPublic, extraData: i32 0)
!2500 = !DIDerivedType(tag: DW_TAG_member, name: "_head", scope: !2496, file: !2497, line: 42, baseType: !34, size: 32, offset: 864)
!2501 = !DIDerivedType(tag: DW_TAG_member, name: "_tail", scope: !2496, file: !2497, line: 43, baseType: !34, size: 32, offset: 896)
!2502 = !DISubprogram(name: "Resize", scope: !2496, file: !2497, line: 27, type: !2503, scopeLine: 27, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!2503 = !DISubroutineType(types: !2504)
!2504 = !{null, !2505}
!2505 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2496, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!2506 = !DISubprogram(name: "class_name", linkageName: "_ZNK6Resize10class_nameEv", scope: !2496, file: !2497, line: 29, type: !2507, scopeLine: 29, containingType: !2496, virtualIndex: 9, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2507 = !DISubroutineType(types: !2508)
!2508 = !{!566, !2509}
!2509 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2510, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!2510 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !2496)
!2511 = !DISubprogram(name: "port_count", linkageName: "_ZNK6Resize10port_countEv", scope: !2496, file: !2497, line: 30, type: !2507, scopeLine: 30, containingType: !2496, virtualIndex: 10, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2512 = !DISubprogram(name: "flags", linkageName: "_ZNK6Resize5flagsEv", scope: !2496, file: !2497, line: 33, type: !2507, scopeLine: 33, containingType: !2496, virtualIndex: 13, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2513 = !DISubprogram(name: "add_handlers", linkageName: "_ZN6Resize12add_handlersEv", scope: !2496, file: !2497, line: 35, type: !2503, scopeLine: 35, containingType: !2496, virtualIndex: 18, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2514 = !DISubprogram(name: "configure", linkageName: "_ZN6Resize9configureER6VectorI6StringEP12ErrorHandler", scope: !2496, file: !2497, line: 36, type: !2515, scopeLine: 36, containingType: !2496, virtualIndex: 17, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2515 = !DISubroutineType(types: !2516)
!2516 = !{!34, !2505, !1458, !1180}
!2517 = !DISubprogram(name: "can_live_reconfigure", linkageName: "_ZNK6Resize20can_live_reconfigureEv", scope: !2496, file: !2497, line: 37, type: !2518, scopeLine: 37, containingType: !2496, virtualIndex: 24, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2518 = !DISubroutineType(types: !2519)
!2519 = !{!53, !2509}
!2520 = !DISubprogram(name: "simple_action", linkageName: "_ZN6Resize13simple_actionEP6Packet", scope: !2496, file: !2497, line: 39, type: !2521, scopeLine: 39, containingType: !2496, virtualIndex: 4, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2521 = !DISubroutineType(types: !2522)
!2522 = !{!78, !2505, !78}
!2523 = !{!2524}
!2524 = !DILocalVariable(name: "this", arg: 1, scope: !2495, type: !2525, flags: DIFlagArtificial | DIFlagObjectPointer)
!2525 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2496, size: 64)
!2526 = !DILocation(line: 0, scope: !2495)
!2527 = !DILocation(line: 14, column: 1, scope: !2495)
!2528 = !DILocation(line: 13, column: 9, scope: !2495)
!2529 = !{!2530, !2530, i64 0}
!2530 = !{!"vtable pointer", !2531, i64 0}
!2531 = !{!"Simple C++ TBAA"}
!2532 = !DILocation(line: 15, column: 1, scope: !2495)
!2533 = distinct !DISubprogram(name: "configure", linkageName: "_ZN6Resize9configureER6VectorI6StringEP12ErrorHandler", scope: !2496, file: !1, line: 19, type: !2515, scopeLine: 20, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2514, retainedNodes: !2534)
!2534 = !{!2535, !2536, !2537}
!2535 = !DILocalVariable(name: "this", arg: 1, scope: !2533, type: !2525, flags: DIFlagArtificial | DIFlagObjectPointer)
!2536 = !DILocalVariable(name: "conf", arg: 2, scope: !2533, file: !1, line: 19, type: !1458)
!2537 = !DILocalVariable(name: "errh", arg: 3, scope: !2533, file: !1, line: 19, type: !1180)
!2538 = !DILocation(line: 0, scope: !2533)
!2539 = !DILocation(line: 22, column: 5, scope: !2533)
!2540 = !DILocation(line: 22, column: 11, scope: !2533)
!2541 = !{!2542, !2543, i64 108}
!2542 = !{!"_ZTS6Resize", !2543, i64 108, !2543, i64 112}
!2543 = !{!"int", !2544, i64 0}
!2544 = !{!"omnipotent char", !2531, i64 0}
!2545 = !DILocation(line: 23, column: 5, scope: !2533)
!2546 = !DILocation(line: 23, column: 11, scope: !2533)
!2547 = !{!2542, !2543, i64 112}
!2548 = !DILocation(line: 24, column: 12, scope: !2533)
!2549 = !DILocation(line: 24, column: 23, scope: !2533)
!2550 = !DILocalVariable(name: "this", arg: 1, scope: !2551, type: !1286, flags: DIFlagArtificial | DIFlagObjectPointer)
!2551 = distinct !DISubprogram(name: "read_p<int>", linkageName: "_ZN4Args6read_pIiEERS_PKcRT_", scope: !1287, file: !1274, line: 377, type: !2552, scopeLine: 377, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1722, declaration: !2554, retainedNodes: !2555)
!2552 = !DISubroutineType(types: !2553)
!2553 = !{!1751, !1730, !566, !1678}
!2554 = !DISubprogram(name: "read_p<int>", linkageName: "_ZN4Args6read_pIiEERS_PKcRT_", scope: !1287, file: !1274, line: 377, type: !2552, scopeLine: 377, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1722)
!2555 = !{!2550, !2556, !2557}
!2556 = !DILocalVariable(name: "keyword", arg: 2, scope: !2551, file: !1274, line: 377, type: !566)
!2557 = !DILocalVariable(name: "x", arg: 3, scope: !2551, file: !1274, line: 377, type: !1678)
!2558 = !DILocation(line: 0, scope: !2551, inlinedAt: !2559)
!2559 = distinct !DILocation(line: 25, column: 10, scope: !2533)
!2560 = !DILocalVariable(name: "this", arg: 1, scope: !2561, type: !1286, flags: DIFlagArtificial | DIFlagObjectPointer)
!2561 = distinct !DISubprogram(name: "read<int>", linkageName: "_ZN4Args4readIiEERS_PKciRT_", scope: !1287, file: !1274, line: 385, type: !2562, scopeLine: 385, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1722, declaration: !2564, retainedNodes: !2565)
!2562 = !DISubroutineType(types: !2563)
!2563 = !{!1751, !1730, !566, !34, !1678}
!2564 = !DISubprogram(name: "read<int>", linkageName: "_ZN4Args4readIiEERS_PKciRT_", scope: !1287, file: !1274, line: 385, type: !2562, scopeLine: 385, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1722)
!2565 = !{!2560, !2566, !2567, !2568}
!2566 = !DILocalVariable(name: "keyword", arg: 2, scope: !2561, file: !1274, line: 385, type: !566)
!2567 = !DILocalVariable(name: "flags", arg: 3, scope: !2561, file: !1274, line: 385, type: !34)
!2568 = !DILocalVariable(name: "x", arg: 4, scope: !2561, file: !1274, line: 385, type: !1678)
!2569 = !DILocation(line: 0, scope: !2561, inlinedAt: !2570)
!2570 = distinct !DILocation(line: 378, column: 16, scope: !2551, inlinedAt: !2559)
!2571 = !DILocation(line: 386, column: 9, scope: !2561, inlinedAt: !2570)
!2572 = !DILocation(line: 0, scope: !2551, inlinedAt: !2573)
!2573 = distinct !DILocation(line: 26, column: 10, scope: !2533)
!2574 = !DILocation(line: 0, scope: !2561, inlinedAt: !2575)
!2575 = distinct !DILocation(line: 378, column: 16, scope: !2551, inlinedAt: !2573)
!2576 = !DILocation(line: 386, column: 9, scope: !2561, inlinedAt: !2575)
!2577 = !DILocation(line: 27, column: 10, scope: !2533)
!2578 = !DILocation(line: 24, column: 5, scope: !2533)
!2579 = !DILocation(line: 28, column: 1, scope: !2533)
!2580 = distinct !DISubprogram(name: "simple_action", linkageName: "_ZN6Resize13simple_actionEP6Packet", scope: !2496, file: !1, line: 39, type: !2521, scopeLine: 40, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2520, retainedNodes: !2581)
!2581 = !{!2582, !2583}
!2582 = !DILocalVariable(name: "this", arg: 1, scope: !2580, type: !2525, flags: DIFlagArtificial | DIFlagObjectPointer)
!2583 = !DILocalVariable(name: "p", arg: 2, scope: !2580, file: !1, line: 39, type: !78)
!2584 = !DILocation(line: 0, scope: !2580)
!2585 = !DILocation(line: 41, column: 9, scope: !2586)
!2586 = distinct !DILexicalBlock(scope: !2580, file: !1, line: 41, column: 9)
!2587 = !DILocation(line: 41, column: 15, scope: !2586)
!2588 = !DILocation(line: 41, column: 9, scope: !2580)
!2589 = !DILocalVariable(name: "this", arg: 1, scope: !2590, type: !78, flags: DIFlagArtificial | DIFlagObjectPointer)
!2590 = distinct !DISubprogram(name: "nonunique_push", linkageName: "_ZN6Packet14nonunique_pushEj", scope: !5, file: !4, line: 1567, type: !281, scopeLine: 1568, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !280, retainedNodes: !2591)
!2591 = !{!2589, !2592}
!2592 = !DILocalVariable(name: "len", arg: 2, scope: !2590, file: !4, line: 1567, type: !12)
!2593 = !DILocation(line: 0, scope: !2590, inlinedAt: !2594)
!2594 = distinct !DILocation(line: 42, column: 16, scope: !2595)
!2595 = distinct !DILexicalBlock(scope: !2586, file: !1, line: 41, column: 20)
!2596 = !DILocalVariable(name: "this", arg: 1, scope: !2597, type: !1100, flags: DIFlagArtificial | DIFlagObjectPointer)
!2597 = distinct !DISubprogram(name: "headroom", linkageName: "_ZNK6Packet8headroomEv", scope: !5, file: !4, line: 969, type: !259, scopeLine: 970, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !261, retainedNodes: !2598)
!2598 = !{!2596}
!2599 = !DILocation(line: 0, scope: !2597, inlinedAt: !2600)
!2600 = distinct !DILocation(line: 1569, column: 9, scope: !2601, inlinedAt: !2594)
!2601 = distinct !DILexicalBlock(scope: !2590, file: !4, line: 1569, column: 9)
!2602 = !DILocation(line: 971, column: 12, scope: !2597, inlinedAt: !2600)
!2603 = !DILocalVariable(name: "this", arg: 1, scope: !2604, type: !1100, flags: DIFlagArtificial | DIFlagObjectPointer)
!2604 = distinct !DISubprogram(name: "buffer", linkageName: "_ZNK6Packet6bufferEv", scope: !5, file: !4, line: 924, type: !253, scopeLine: 925, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !263, retainedNodes: !2605)
!2605 = !{!2603}
!2606 = !DILocation(line: 0, scope: !2604, inlinedAt: !2607)
!2607 = distinct !DILocation(line: 971, column: 21, scope: !2597, inlinedAt: !2600)
!2608 = !DILocation(line: 929, column: 12, scope: !2604, inlinedAt: !2607)
!2609 = !{!2610, !2612, i64 16}
!2610 = !{!"_ZTS6Packet", !2611, i64 0, !2612, i64 8, !2612, i64 16, !2612, i64 24, !2612, i64 32, !2612, i64 40, !2613, i64 48, !2612, i64 152, !2612, i64 160}
!2611 = !{!"_ZTS15atomic_uint32_t", !2543, i64 0}
!2612 = !{!"any pointer", !2544, i64 0}
!2613 = !{!"_ZTSN6Packet7AllAnnoE", !2544, i64 0, !2612, i64 48, !2612, i64 56, !2612, i64 64, !2614, i64 72, !2544, i64 76, !2612, i64 88, !2612, i64 96}
!2614 = !{!"_ZTSN6Packet10PacketTypeE", !2544, i64 0}
!2615 = !DILocation(line: 971, column: 19, scope: !2597, inlinedAt: !2600)
!2616 = !DILocation(line: 1569, column: 20, scope: !2601, inlinedAt: !2594)
!2617 = !DILocation(line: 1569, column: 9, scope: !2590, inlinedAt: !2594)
!2618 = !DILocation(line: 1573, column: 2, scope: !2619, inlinedAt: !2594)
!2619 = distinct !DILexicalBlock(scope: !2601, file: !4, line: 1569, column: 28)
!2620 = !DILocation(line: 1573, column: 8, scope: !2619, inlinedAt: !2594)
!2621 = !{!2610, !2612, i64 24}
!2622 = !DILocation(line: 43, column: 13, scope: !2595)
!2623 = !DILocation(line: 1582, column: 9, scope: !2601, inlinedAt: !2594)
!2624 = !DILocation(line: 43, column: 14, scope: !2625)
!2625 = distinct !DILexicalBlock(scope: !2595, file: !1, line: 43, column: 13)
!2626 = !DILocation(line: 45, column: 9, scope: !2627)
!2627 = distinct !DILexicalBlock(scope: !2580, file: !1, line: 45, column: 9)
!2628 = !DILocation(line: 45, column: 15, scope: !2627)
!2629 = !DILocation(line: 45, column: 9, scope: !2580)
!2630 = !DILocation(line: 46, column: 30, scope: !2631)
!2631 = distinct !DILexicalBlock(scope: !2627, file: !1, line: 45, column: 20)
!2632 = !DILocation(line: 46, column: 41, scope: !2631)
!2633 = !DILocalVariable(name: "amount", arg: 1, scope: !2634, file: !1, line: 31, type: !12)
!2634 = distinct !DISubprogram(name: "check_length", linkageName: "_ZL12check_lengthjj", scope: !1, file: !1, line: 31, type: !2635, scopeLine: 32, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !2637)
!2635 = !DISubroutineType(types: !2636)
!2636 = !{!12, !12, !12}
!2637 = !{!2633, !2638}
!2638 = !DILocalVariable(name: "max", arg: 2, scope: !2634, file: !1, line: 31, type: !12)
!2639 = !DILocation(line: 0, scope: !2634, inlinedAt: !2640)
!2640 = distinct !DILocation(line: 46, column: 17, scope: !2631)
!2641 = !DILocation(line: 33, column: 16, scope: !2642, inlinedAt: !2640)
!2642 = distinct !DILexicalBlock(scope: !2634, file: !1, line: 33, column: 9)
!2643 = !DILocation(line: 46, column: 12, scope: !2631)
!2644 = !DILocation(line: 47, column: 5, scope: !2631)
!2645 = !DILocation(line: 48, column: 9, scope: !2646)
!2646 = distinct !DILexicalBlock(scope: !2580, file: !1, line: 48, column: 9)
!2647 = !DILocation(line: 48, column: 15, scope: !2646)
!2648 = !DILocation(line: 48, column: 9, scope: !2580)
!2649 = !DILocalVariable(name: "this", arg: 1, scope: !2650, type: !78, flags: DIFlagArtificial | DIFlagObjectPointer)
!2650 = distinct !DISubprogram(name: "nonunique_put", linkageName: "_ZN6Packet13nonunique_putEj", scope: !5, file: !4, line: 1624, type: !281, scopeLine: 1625, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !287, retainedNodes: !2651)
!2651 = !{!2649, !2652}
!2652 = !DILocalVariable(name: "len", arg: 2, scope: !2650, file: !4, line: 1624, type: !12)
!2653 = !DILocation(line: 0, scope: !2650, inlinedAt: !2654)
!2654 = distinct !DILocation(line: 49, column: 16, scope: !2655)
!2655 = distinct !DILexicalBlock(scope: !2646, file: !1, line: 48, column: 20)
!2656 = !DILocalVariable(name: "this", arg: 1, scope: !2657, type: !1100, flags: DIFlagArtificial | DIFlagObjectPointer)
!2657 = distinct !DISubprogram(name: "tailroom", linkageName: "_ZNK6Packet8tailroomEv", scope: !5, file: !4, line: 980, type: !259, scopeLine: 981, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !262, retainedNodes: !2658)
!2658 = !{!2656}
!2659 = !DILocation(line: 0, scope: !2657, inlinedAt: !2660)
!2660 = distinct !DILocation(line: 1626, column: 9, scope: !2661, inlinedAt: !2654)
!2661 = distinct !DILexicalBlock(scope: !2650, file: !4, line: 1626, column: 9)
!2662 = !DILocalVariable(name: "this", arg: 1, scope: !2663, type: !1100, flags: DIFlagArtificial | DIFlagObjectPointer)
!2663 = distinct !DISubprogram(name: "end_buffer", linkageName: "_ZNK6Packet10end_bufferEv", scope: !5, file: !4, line: 938, type: !253, scopeLine: 939, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !264, retainedNodes: !2664)
!2664 = !{!2662}
!2665 = !DILocation(line: 0, scope: !2663, inlinedAt: !2666)
!2666 = distinct !DILocation(line: 982, column: 12, scope: !2657, inlinedAt: !2660)
!2667 = !DILocation(line: 947, column: 12, scope: !2663, inlinedAt: !2666)
!2668 = !{!2610, !2612, i64 40}
!2669 = !DILocation(line: 982, column: 27, scope: !2657, inlinedAt: !2660)
!2670 = !DILocation(line: 982, column: 25, scope: !2657, inlinedAt: !2660)
!2671 = !DILocation(line: 982, column: 12, scope: !2657, inlinedAt: !2660)
!2672 = !DILocation(line: 1626, column: 20, scope: !2661, inlinedAt: !2654)
!2673 = !DILocation(line: 1626, column: 9, scope: !2650, inlinedAt: !2654)
!2674 = !DILocation(line: 1630, column: 2, scope: !2675, inlinedAt: !2654)
!2675 = distinct !DILexicalBlock(scope: !2661, file: !4, line: 1626, column: 28)
!2676 = !DILocation(line: 1630, column: 8, scope: !2675, inlinedAt: !2654)
!2677 = !{!2610, !2612, i64 32}
!2678 = !DILocation(line: 50, column: 13, scope: !2655)
!2679 = !DILocation(line: 1638, column: 9, scope: !2661, inlinedAt: !2654)
!2680 = !DILocation(line: 50, column: 14, scope: !2681)
!2681 = distinct !DILexicalBlock(scope: !2655, file: !1, line: 50, column: 13)
!2682 = !DILocation(line: 52, column: 9, scope: !2683)
!2683 = distinct !DILexicalBlock(scope: !2580, file: !1, line: 52, column: 9)
!2684 = !DILocation(line: 52, column: 15, scope: !2683)
!2685 = !DILocation(line: 52, column: 9, scope: !2580)
!2686 = !DILocation(line: 53, column: 30, scope: !2687)
!2687 = distinct !DILexicalBlock(scope: !2683, file: !1, line: 52, column: 20)
!2688 = !DILocation(line: 53, column: 41, scope: !2687)
!2689 = !DILocation(line: 0, scope: !2634, inlinedAt: !2690)
!2690 = distinct !DILocation(line: 53, column: 17, scope: !2687)
!2691 = !DILocation(line: 33, column: 16, scope: !2642, inlinedAt: !2690)
!2692 = !DILocation(line: 53, column: 12, scope: !2687)
!2693 = !DILocation(line: 54, column: 5, scope: !2687)
!2694 = !DILocation(line: 56, column: 1, scope: !2580)
!2695 = distinct !DISubprogram(name: "add_handlers", linkageName: "_ZN6Resize12add_handlersEv", scope: !2496, file: !1, line: 60, type: !2503, scopeLine: 61, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2513, retainedNodes: !2696)
!2696 = !{!2697}
!2697 = !DILocalVariable(name: "this", arg: 1, scope: !2695, type: !2525, flags: DIFlagArtificial | DIFlagObjectPointer)
!2698 = !DILocation(line: 0, scope: !2695)
!2699 = !DILocation(line: 62, column: 5, scope: !2695)
!2700 = !DILocation(line: 62, column: 70, scope: !2695)
!2701 = !DILocation(line: 63, column: 70, scope: !2695)
!2702 = !DILocation(line: 63, column: 5, scope: !2695)
!2703 = !DILocation(line: 64, column: 1, scope: !2695)
!2704 = distinct !DISubprogram(name: "~Resize", linkageName: "_ZN6ResizeD0Ev", scope: !2496, file: !2497, line: 25, type: !2503, scopeLine: 25, flags: DIFlagArtificial | DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2705, retainedNodes: !2706)
!2705 = !DISubprogram(name: "~Resize", scope: !2496, type: !2503, containingType: !2496, virtualIndex: 0, flags: DIFlagPublic | DIFlagArtificial | DIFlagPrototyped, spFlags: DISPFlagVirtual | DISPFlagOptimized)
!2706 = !{!2707}
!2707 = !DILocalVariable(name: "this", arg: 1, scope: !2704, type: !2525, flags: DIFlagArtificial | DIFlagObjectPointer)
!2708 = !DILocation(line: 0, scope: !2704)
!2709 = !DILocation(line: 25, column: 7, scope: !2704)
!2710 = distinct !DISubprogram(name: "class_name", linkageName: "_ZNK6Resize10class_nameEv", scope: !2496, file: !2497, line: 29, type: !2507, scopeLine: 29, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2506, retainedNodes: !2711)
!2711 = !{!2712}
!2712 = !DILocalVariable(name: "this", arg: 1, scope: !2710, type: !2713, flags: DIFlagArtificial | DIFlagObjectPointer)
!2713 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2510, size: 64)
!2714 = !DILocation(line: 0, scope: !2710)
!2715 = !DILocation(line: 29, column: 38, scope: !2710)
!2716 = distinct !DISubprogram(name: "port_count", linkageName: "_ZNK6Resize10port_countEv", scope: !2496, file: !2497, line: 30, type: !2507, scopeLine: 30, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2511, retainedNodes: !2717)
!2717 = !{!2718}
!2718 = !DILocalVariable(name: "this", arg: 1, scope: !2716, type: !2713, flags: DIFlagArtificial | DIFlagObjectPointer)
!2719 = !DILocation(line: 0, scope: !2716)
!2720 = !DILocation(line: 30, column: 38, scope: !2716)
!2721 = distinct !DISubprogram(name: "flags", linkageName: "_ZNK6Resize5flagsEv", scope: !2496, file: !2497, line: 33, type: !2507, scopeLine: 33, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2512, retainedNodes: !2722)
!2722 = !{!2723}
!2723 = !DILocalVariable(name: "this", arg: 1, scope: !2721, type: !2713, flags: DIFlagArtificial | DIFlagObjectPointer)
!2724 = !DILocation(line: 0, scope: !2721)
!2725 = !DILocation(line: 33, column: 38, scope: !2721)
!2726 = distinct !DISubprogram(name: "can_live_reconfigure", linkageName: "_ZNK6Resize20can_live_reconfigureEv", scope: !2496, file: !2497, line: 37, type: !2518, scopeLine: 37, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2517, retainedNodes: !2727)
!2727 = !{!2728}
!2728 = !DILocalVariable(name: "this", arg: 1, scope: !2726, type: !2713, flags: DIFlagArtificial | DIFlagObjectPointer)
!2729 = !DILocation(line: 0, scope: !2726)
!2730 = !DILocation(line: 37, column: 41, scope: !2726)
!2731 = distinct !DISubprogram(name: "args_base_read<int>", linkageName: "_Z14args_base_readIiEvP4ArgsPKciRT_", scope: !1274, file: !1274, line: 928, type: !1284, scopeLine: 929, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1722, retainedNodes: !2732)
!2732 = !{!2733, !2734, !2735, !2736}
!2733 = !DILocalVariable(name: "args", arg: 1, scope: !2731, file: !1274, line: 928, type: !1286)
!2734 = !DILocalVariable(name: "keyword", arg: 2, scope: !2731, file: !1274, line: 928, type: !566)
!2735 = !DILocalVariable(name: "flags", arg: 3, scope: !2731, file: !1274, line: 928, type: !34)
!2736 = !DILocalVariable(name: "variable", arg: 4, scope: !2731, file: !1274, line: 928, type: !1678)
!2737 = !{!2612, !2612, i64 0}
!2738 = !DILocation(line: 928, column: 27, scope: !2731)
!2739 = !DILocation(line: 928, column: 45, scope: !2731)
!2740 = !{!2543, !2543, i64 0}
!2741 = !DILocation(line: 928, column: 58, scope: !2731)
!2742 = !DILocation(line: 928, column: 68, scope: !2731)
!2743 = !DILocation(line: 930, column: 5, scope: !2731)
!2744 = !DILocation(line: 930, column: 21, scope: !2731)
!2745 = !DILocation(line: 930, column: 30, scope: !2731)
!2746 = !DILocation(line: 930, column: 37, scope: !2731)
!2747 = !DILocation(line: 930, column: 11, scope: !2731)
!2748 = !DILocation(line: 931, column: 1, scope: !2731)
!2749 = distinct !DISubprogram(name: "base_read<int>", linkageName: "_ZN4Args9base_readIiEEvPKciRT_", scope: !1287, file: !1274, line: 731, type: !2750, scopeLine: 731, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1722, declaration: !2752, retainedNodes: !2753)
!2750 = !DISubroutineType(types: !2751)
!2751 = !{null, !1730, !566, !34, !1678}
!2752 = !DISubprogram(name: "base_read<int>", linkageName: "_ZN4Args9base_readIiEEvPKciRT_", scope: !1287, file: !1274, line: 731, type: !2750, scopeLine: 731, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1722)
!2753 = !{!2754, !2755, !2756, !2757, !2758, !2759, !2761}
!2754 = !DILocalVariable(name: "this", arg: 1, scope: !2749, type: !1286, flags: DIFlagArtificial | DIFlagObjectPointer)
!2755 = !DILocalVariable(name: "keyword", arg: 2, scope: !2749, file: !1274, line: 731, type: !566)
!2756 = !DILocalVariable(name: "flags", arg: 3, scope: !2749, file: !1274, line: 731, type: !34)
!2757 = !DILocalVariable(name: "variable", arg: 4, scope: !2749, file: !1274, line: 731, type: !1678)
!2758 = !DILocalVariable(name: "slot_status", scope: !2749, file: !1274, line: 732, type: !1724)
!2759 = !DILocalVariable(name: "str", scope: !2760, file: !1274, line: 733, type: !554)
!2760 = distinct !DILexicalBlock(scope: !2749, file: !1274, line: 733, column: 20)
!2761 = !DILocalVariable(name: "s", scope: !2762, file: !1274, line: 734, type: !1653)
!2762 = distinct !DILexicalBlock(scope: !2760, file: !1274, line: 733, column: 61)
!2763 = !DILocation(line: 1056, column: 19, scope: !1816, inlinedAt: !2764)
!2764 = distinct !DILocation(line: 1072, column: 14, scope: !2765, inlinedAt: !2774)
!2765 = distinct !DILexicalBlock(scope: !2766, file: !1274, line: 1072, column: 13)
!2766 = distinct !DISubprogram(name: "parse<int>", linkageName: "_ZN6IntArg5parseIiEEbRK6StringRT_RK10ArgContext", scope: !1817, file: !1274, line: 1070, type: !1838, scopeLine: 1070, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1841, declaration: !2767, retainedNodes: !2768)
!2767 = !DISubprogram(name: "parse<int>", linkageName: "_ZN6IntArg5parseIiEEbRK6StringRT_RK10ArgContext", scope: !1817, file: !1274, line: 1070, type: !1838, scopeLine: 1070, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1841)
!2768 = !{!2769, !2770, !2771, !2772, !2773}
!2769 = !DILocalVariable(name: "this", arg: 1, scope: !2766, type: !1845, flags: DIFlagArtificial | DIFlagObjectPointer)
!2770 = !DILocalVariable(name: "str", arg: 2, scope: !2766, file: !1274, line: 1070, type: !595)
!2771 = !DILocalVariable(name: "result", arg: 3, scope: !2766, file: !1274, line: 1070, type: !1678)
!2772 = !DILocalVariable(name: "args", arg: 4, scope: !2766, file: !1274, line: 1070, type: !1837)
!2773 = !DILocalVariable(name: "x", scope: !2766, file: !1274, line: 1071, type: !34)
!2774 = distinct !DILocation(line: 109, column: 23, scope: !2775, inlinedAt: !2793)
!2775 = distinct !DISubprogram(name: "parse<int, Args>", linkageName: "_ZN17Args_parse_helperI10DefaultArgIiELb0EE5parseIi4ArgsEEbS1_RK6StringRT_RT0_", scope: !2776, file: !1274, line: 108, type: !2783, scopeLine: 108, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !2786, declaration: !2785, retainedNodes: !2788)
!2776 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "Args_parse_helper<DefaultArg<int>, false>", file: !1274, line: 98, size: 8, flags: DIFlagTypePassByValue, elements: !452, templateParams: !2777, identifier: "_ZTS17Args_parse_helperI10DefaultArgIiELb0EE")
!2777 = !{!2778, !2782}
!2778 = !DITemplateTypeParameter(name: "P", type: !2779)
!2779 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "DefaultArg<int>", file: !1274, line: 1183, size: 64, flags: DIFlagTypePassByValue | DIFlagNonTrivial, elements: !2780, templateParams: !1722, identifier: "_ZTS10DefaultArgIiE")
!2780 = !{!2781}
!2781 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !2779, baseType: !1817, extraData: i32 0)
!2782 = !DITemplateValueParameter(name: "direct", type: !53, value: i8 0)
!2783 = !DISubroutineType(types: !2784)
!2784 = !{!53, !2779, !595, !1678, !1751}
!2785 = !DISubprogram(name: "parse<int, Args>", linkageName: "_ZN17Args_parse_helperI10DefaultArgIiELb0EE5parseIi4ArgsEEbS1_RK6StringRT_RT0_", scope: !2776, file: !1274, line: 108, type: !2783, scopeLine: 108, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized, templateParams: !2786)
!2786 = !{!1628, !2787}
!2787 = !DITemplateTypeParameter(name: "A", type: !1287)
!2788 = !{!2789, !2790, !2791, !2792}
!2789 = !DILocalVariable(name: "parser", arg: 1, scope: !2775, file: !1274, line: 108, type: !2779)
!2790 = !DILocalVariable(name: "str", arg: 2, scope: !2775, file: !1274, line: 108, type: !595)
!2791 = !DILocalVariable(name: "s", arg: 3, scope: !2775, file: !1274, line: 108, type: !1678)
!2792 = !DILocalVariable(name: "args", arg: 4, scope: !2775, file: !1274, line: 108, type: !1751)
!2793 = distinct !DILocation(line: 735, column: 28, scope: !2762)
!2794 = !DILocation(line: 0, scope: !2749)
!2795 = !DILocation(line: 732, column: 9, scope: !2749)
!2796 = !DILocation(line: 733, column: 20, scope: !2749)
!2797 = !DILocation(line: 733, column: 20, scope: !2760)
!2798 = !DILocation(line: 733, column: 26, scope: !2760)
!2799 = !DILocalVariable(name: "this", arg: 1, scope: !2800, type: !1359, flags: DIFlagArtificial | DIFlagObjectPointer)
!2800 = distinct !DISubprogram(name: "operator int (String::*)() const", linkageName: "_ZNK6StringcvMS_KFivEEv", scope: !554, file: !555, line: 564, type: !682, scopeLine: 564, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !681, retainedNodes: !2801)
!2801 = !{!2799}
!2802 = !DILocation(line: 0, scope: !2800, inlinedAt: !2803)
!2803 = distinct !DILocation(line: 733, column: 20, scope: !2760)
!2804 = !DILocation(line: 565, column: 16, scope: !2800, inlinedAt: !2803)
!2805 = !{!2806, !2543, i64 8}
!2806 = !{!"_ZTS6String", !2807, i64 0}
!2807 = !{!"_ZTSN6String5rep_tE", !2612, i64 0, !2543, i64 8, !2612, i64 16}
!2808 = !DILocation(line: 565, column: 23, scope: !2800, inlinedAt: !2803)
!2809 = !DILocation(line: 565, column: 13, scope: !2800, inlinedAt: !2803)
!2810 = !DILocalVariable(name: "variable", arg: 1, scope: !2811, file: !1274, line: 100, type: !1678)
!2811 = distinct !DISubprogram(name: "slot<int, Args>", linkageName: "_ZN17Args_parse_helperI10DefaultArgIiELb0EE4slotIi4ArgsEEPT_RS5_RT0_", scope: !2776, file: !1274, line: 100, type: !2812, scopeLine: 100, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !2786, declaration: !2814, retainedNodes: !2815)
!2812 = !DISubroutineType(types: !2813)
!2813 = !{!1653, !1678, !1751}
!2814 = !DISubprogram(name: "slot<int, Args>", linkageName: "_ZN17Args_parse_helperI10DefaultArgIiELb0EE4slotIi4ArgsEEPT_RS5_RT0_", scope: !2776, file: !1274, line: 100, type: !2812, scopeLine: 100, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized, templateParams: !2786)
!2815 = !{!2810, !2816}
!2816 = !DILocalVariable(name: "args", arg: 2, scope: !2811, file: !1274, line: 100, type: !1751)
!2817 = !DILocation(line: 0, scope: !2811, inlinedAt: !2818)
!2818 = distinct !DILocation(line: 734, column: 20, scope: !2762)
!2819 = !DILocalVariable(name: "this", arg: 1, scope: !2820, type: !1286, flags: DIFlagArtificial | DIFlagObjectPointer)
!2820 = distinct !DISubprogram(name: "slot<int>", linkageName: "_ZN4Args4slotIiEEPT_RS1_", scope: !1287, file: !1274, line: 701, type: !2821, scopeLine: 701, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !1722, declaration: !2823, retainedNodes: !2824)
!2821 = !DISubroutineType(types: !2822)
!2822 = !{!1653, !1730, !1678}
!2823 = !DISubprogram(name: "slot<int>", linkageName: "_ZN4Args4slotIiEEPT_RS1_", scope: !1287, file: !1274, line: 701, type: !2821, scopeLine: 701, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized, templateParams: !1722)
!2824 = !{!2819, !2825}
!2825 = !DILocalVariable(name: "x", arg: 2, scope: !2820, file: !1274, line: 701, type: !1678)
!2826 = !DILocation(line: 0, scope: !2820, inlinedAt: !2827)
!2827 = distinct !DILocation(line: 101, column: 21, scope: !2811, inlinedAt: !2818)
!2828 = !DILocation(line: 703, column: 54, scope: !2829, inlinedAt: !2827)
!2829 = distinct !DILexicalBlock(scope: !2820, file: !1274, line: 702, column: 13)
!2830 = !DILocation(line: 703, column: 42, scope: !2829, inlinedAt: !2827)
!2831 = !DILocation(line: 703, column: 20, scope: !2829, inlinedAt: !2827)
!2832 = !DILocation(line: 0, scope: !2762)
!2833 = !DILocation(line: 735, column: 23, scope: !2762)
!2834 = !DILocation(line: 735, column: 25, scope: !2762)
!2835 = !DILocation(line: 0, scope: !2775, inlinedAt: !2793)
!2836 = !DILocation(line: 109, column: 16, scope: !2775, inlinedAt: !2793)
!2837 = !DILocation(line: 109, column: 37, scope: !2775, inlinedAt: !2793)
!2838 = !DILocation(line: 0, scope: !2766, inlinedAt: !2774)
!2839 = !DILocation(line: 0, scope: !1816, inlinedAt: !2764)
!2840 = !DILocation(line: 1056, column: 9, scope: !1816, inlinedAt: !2764)
!2841 = !DILocalVariable(name: "this", arg: 1, scope: !2842, type: !1359, flags: DIFlagArtificial | DIFlagObjectPointer)
!2842 = distinct !DISubprogram(name: "begin", linkageName: "_ZNK6String5beginEv", scope: !554, file: !555, line: 551, type: !691, scopeLine: 551, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !690, retainedNodes: !2843)
!2843 = !{!2841}
!2844 = !DILocation(line: 0, scope: !2842, inlinedAt: !2845)
!2845 = distinct !DILocation(line: 1057, column: 23, scope: !2846, inlinedAt: !2764)
!2846 = distinct !DILexicalBlock(scope: !1816, file: !1274, line: 1057, column: 13)
!2847 = !DILocation(line: 552, column: 15, scope: !2842, inlinedAt: !2845)
!2848 = !{!2806, !2612, i64 0}
!2849 = !DILocalVariable(name: "this", arg: 1, scope: !2850, type: !1359, flags: DIFlagArtificial | DIFlagObjectPointer)
!2850 = distinct !DISubprogram(name: "end", linkageName: "_ZNK6String3endEv", scope: !554, file: !555, line: 559, type: !691, scopeLine: 559, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !694, retainedNodes: !2851)
!2851 = !{!2849}
!2852 = !DILocation(line: 0, scope: !2850, inlinedAt: !2853)
!2853 = distinct !DILocation(line: 1057, column: 36, scope: !2846, inlinedAt: !2764)
!2854 = !DILocation(line: 560, column: 25, scope: !2850, inlinedAt: !2853)
!2855 = !DILocation(line: 560, column: 20, scope: !2850, inlinedAt: !2853)
!2856 = !DILocation(line: 1057, column: 70, scope: !2846, inlinedAt: !2764)
!2857 = !DILocation(line: 1057, column: 13, scope: !2846, inlinedAt: !2764)
!2858 = !DILocation(line: 0, scope: !2850, inlinedAt: !2859)
!2859 = distinct !DILocation(line: 1058, column: 20, scope: !2846, inlinedAt: !2764)
!2860 = !DILocation(line: 560, column: 15, scope: !2850, inlinedAt: !2859)
!2861 = !DILocation(line: 560, column: 25, scope: !2850, inlinedAt: !2859)
!2862 = !DILocation(line: 560, column: 20, scope: !2850, inlinedAt: !2859)
!2863 = !DILocation(line: 1058, column: 13, scope: !2846, inlinedAt: !2764)
!2864 = !DILocation(line: 1057, column: 13, scope: !1816, inlinedAt: !2764)
!2865 = !DILocation(line: 1059, column: 20, scope: !2846, inlinedAt: !2764)
!2866 = !{!2867, !2543, i64 4}
!2867 = !{!"_ZTS6IntArg", !2543, i64 0, !2543, i64 4}
!2868 = !DILocation(line: 1060, column: 20, scope: !2869, inlinedAt: !2764)
!2869 = distinct !DILexicalBlock(scope: !1816, file: !1274, line: 1060, column: 13)
!2870 = !DILocation(line: 1060, column: 13, scope: !2869, inlinedAt: !2764)
!2871 = !DILocation(line: 1061, column: 18, scope: !2872, inlinedAt: !2764)
!2872 = distinct !DILexicalBlock(scope: !2869, file: !1274, line: 1060, column: 47)
!2873 = !DILocation(line: 1067, column: 5, scope: !1816, inlinedAt: !2764)
!2874 = !DILocation(line: 1073, column: 13, scope: !2765, inlinedAt: !2774)
!2875 = !DILocalVariable(name: "x", arg: 1, scope: !2876, file: !1439, line: 515, type: !2879)
!2876 = distinct !DISubprogram(name: "extract_integer<unsigned int, unsigned int>", linkageName: "_Z15extract_integerIjjEvPKT_RT0_", scope: !1439, file: !1439, line: 515, type: !2877, scopeLine: 515, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, templateParams: !2884, retainedNodes: !2882)
!2877 = !DISubroutineType(types: !2878)
!2878 = !{null, !2879, !2881}
!2879 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2880, size: 64)
!2880 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !16)
!2881 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !16, size: 64)
!2882 = !{!2875, !2883}
!2883 = !DILocalVariable(name: "value", arg: 2, scope: !2876, file: !1439, line: 515, type: !2881)
!2884 = !{!2885, !2886}
!2885 = !DITemplateTypeParameter(name: "Limb", type: !16)
!2886 = !DITemplateTypeParameter(name: "V", type: !16)
!2887 = !DILocation(line: 0, scope: !2876, inlinedAt: !2888)
!2888 = distinct !DILocation(line: 1065, column: 9, scope: !1816, inlinedAt: !2764)
!2889 = !DILocalVariable(name: "x", arg: 1, scope: !2890, file: !1439, line: 508, type: !2879)
!2890 = distinct !DISubprogram(name: "extract", linkageName: "_ZN22extract_integer_helperILi1EjjE7extractEPKjRj", scope: !2891, file: !1439, line: 508, type: !2877, scopeLine: 508, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !2893, retainedNodes: !2896)
!2891 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "extract_integer_helper<1, unsigned int, unsigned int>", file: !1439, line: 507, size: 8, flags: DIFlagTypePassByValue, elements: !2892, templateParams: !2894, identifier: "_ZTS22extract_integer_helperILi1EjjE")
!2892 = !{!2893}
!2893 = !DISubprogram(name: "extract", linkageName: "_ZN22extract_integer_helperILi1EjjE7extractEPKjRj", scope: !2891, file: !1439, line: 508, type: !2877, scopeLine: 508, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!2894 = !{!2895, !2885, !2886}
!2895 = !DITemplateValueParameter(name: "n", type: !34, value: i32 1)
!2896 = !{!2889, !2897}
!2897 = !DILocalVariable(name: "value", arg: 2, scope: !2890, file: !1439, line: 508, type: !2881)
!2898 = !DILocation(line: 0, scope: !2890, inlinedAt: !2899)
!2899 = distinct !DILocation(line: 516, column: 5, scope: !2876, inlinedAt: !2888)
!2900 = !DILocation(line: 509, column: 10, scope: !2890, inlinedAt: !2899)
!2901 = !DILocation(line: 1073, column: 24, scope: !2765, inlinedAt: !2774)
!2902 = !DILocation(line: 1077, column: 43, scope: !2903, inlinedAt: !2774)
!2903 = distinct !DILexicalBlock(scope: !2904, file: !1274, line: 1075, column: 42)
!2904 = distinct !DILexicalBlock(scope: !2765, file: !1274, line: 1075, column: 18)
!2905 = !DILocation(line: 1076, column: 13, scope: !2903, inlinedAt: !2774)
!2906 = !DILocation(line: 1080, column: 20, scope: !2907, inlinedAt: !2774)
!2907 = distinct !DILexicalBlock(scope: !2904, file: !1274, line: 1079, column: 16)
!2908 = !DILocation(line: 1081, column: 13, scope: !2907, inlinedAt: !2774)
!2909 = !DILocation(line: 0, scope: !2765, inlinedAt: !2774)
!2910 = !DILocation(line: 109, column: 9, scope: !2775, inlinedAt: !2793)
!2911 = !DILocation(line: 735, column: 103, scope: !2762)
!2912 = !DILocation(line: 735, column: 13, scope: !2762)
!2913 = !DILocation(line: 737, column: 5, scope: !2762)
!2914 = !DILocalVariable(name: "this", arg: 1, scope: !2915, type: !1355, flags: DIFlagArtificial | DIFlagObjectPointer)
!2915 = distinct !DISubprogram(name: "~String", linkageName: "_ZN6StringD2Ev", scope: !554, file: !555, line: 407, type: !589, scopeLine: 407, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !648, retainedNodes: !2916)
!2916 = !{!2914}
!2917 = !DILocation(line: 0, scope: !2915, inlinedAt: !2918)
!2918 = distinct !DILocation(line: 733, column: 20, scope: !2749)
!2919 = !DILocalVariable(name: "this", arg: 1, scope: !2920, type: !1359, flags: DIFlagArtificial | DIFlagObjectPointer)
!2920 = distinct !DISubprogram(name: "deref", linkageName: "_ZNK6String5derefEv", scope: !554, file: !555, line: 271, type: !819, scopeLine: 271, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !818, retainedNodes: !2921)
!2921 = !{!2919}
!2922 = !DILocation(line: 0, scope: !2920, inlinedAt: !2923)
!2923 = distinct !DILocation(line: 408, column: 5, scope: !2924, inlinedAt: !2918)
!2924 = distinct !DILexicalBlock(scope: !2915, file: !555, line: 407, column: 26)
!2925 = !DILocation(line: 272, column: 9, scope: !2926, inlinedAt: !2923)
!2926 = distinct !DILexicalBlock(scope: !2920, file: !555, line: 272, column: 6)
!2927 = !{!2806, !2612, i64 16}
!2928 = !DILocation(line: 272, column: 6, scope: !2926, inlinedAt: !2923)
!2929 = !DILocation(line: 272, column: 6, scope: !2920, inlinedAt: !2923)
!2930 = !DILocation(line: 273, column: 6, scope: !2931, inlinedAt: !2923)
!2931 = distinct !DILexicalBlock(scope: !2926, file: !555, line: 272, column: 15)
!2932 = !{!2933, !2543, i64 0}
!2933 = !{!"_ZTSN6String6memo_tE", !2543, i64 0, !2543, i64 4, !2543, i64 8, !2544, i64 12}
!2934 = !DILocalVariable(name: "x", arg: 1, scope: !2935, file: !9, line: 382, type: !63)
!2935 = distinct !DISubprogram(name: "dec_and_test", linkageName: "_ZN15atomic_uint32_t12dec_and_testERVj", scope: !8, file: !9, line: 382, type: !69, scopeLine: 383, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !68, retainedNodes: !2936)
!2936 = !{!2934}
!2937 = !DILocation(line: 0, scope: !2935, inlinedAt: !2938)
!2938 = distinct !DILocation(line: 274, column: 10, scope: !2939, inlinedAt: !2923)
!2939 = distinct !DILexicalBlock(scope: !2931, file: !555, line: 274, column: 10)
!2940 = !DILocation(line: 395, column: 13, scope: !2935, inlinedAt: !2938)
!2941 = !DILocation(line: 395, column: 17, scope: !2935, inlinedAt: !2938)
!2942 = !DILocation(line: 274, column: 10, scope: !2931, inlinedAt: !2923)
!2943 = !DILocation(line: 275, column: 3, scope: !2939, inlinedAt: !2923)
!2944 = !DILocation(line: 276, column: 14, scope: !2931, inlinedAt: !2923)
!2945 = !DILocation(line: 277, column: 2, scope: !2931, inlinedAt: !2923)
!2946 = !DILocation(line: 408, column: 5, scope: !2924, inlinedAt: !2918)
!2947 = !DILocation(line: 737, column: 5, scope: !2749)
!2948 = !DILocation(line: 0, scope: !2915, inlinedAt: !2949)
!2949 = distinct !DILocation(line: 733, column: 20, scope: !2749)
!2950 = !DILocation(line: 0, scope: !2920, inlinedAt: !2951)
!2951 = distinct !DILocation(line: 408, column: 5, scope: !2924, inlinedAt: !2949)
!2952 = !DILocation(line: 272, column: 9, scope: !2926, inlinedAt: !2951)
!2953 = !DILocation(line: 272, column: 6, scope: !2926, inlinedAt: !2951)
!2954 = !DILocation(line: 272, column: 6, scope: !2920, inlinedAt: !2951)
!2955 = !DILocation(line: 273, column: 6, scope: !2931, inlinedAt: !2951)
!2956 = !DILocation(line: 0, scope: !2935, inlinedAt: !2957)
!2957 = distinct !DILocation(line: 274, column: 10, scope: !2939, inlinedAt: !2951)
!2958 = !DILocation(line: 395, column: 13, scope: !2935, inlinedAt: !2957)
!2959 = !DILocation(line: 395, column: 17, scope: !2935, inlinedAt: !2957)
!2960 = !DILocation(line: 274, column: 10, scope: !2931, inlinedAt: !2951)
!2961 = !DILocation(line: 275, column: 3, scope: !2939, inlinedAt: !2951)
!2962 = !DILocation(line: 276, column: 14, scope: !2931, inlinedAt: !2951)
!2963 = !DILocation(line: 277, column: 2, scope: !2931, inlinedAt: !2951)
!2964 = !DILocation(line: 408, column: 5, scope: !2924, inlinedAt: !2949)
!2965 = distinct !DISubprogram(name: "length", linkageName: "_ZNK6String6lengthEv", scope: !554, file: !555, line: 484, type: !678, scopeLine: 484, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, declaration: !677, retainedNodes: !2966)
!2966 = !{!2967}
!2967 = !DILocalVariable(name: "this", arg: 1, scope: !2965, type: !1359, flags: DIFlagArtificial | DIFlagObjectPointer)
!2968 = !DILocation(line: 0, scope: !2965)
!2969 = !DILocation(line: 485, column: 15, scope: !2965)
!2970 = !DILocation(line: 485, column: 5, scope: !2965)
