@bitmask ErrorCode::DWORD begin
  ERROR_INVALID_FUNCTION = 1
  ERROR_FILE_NOT_FOUND = 2
  ERROR_PATH_NOT_FOUND = 3
  ERROR_TOO_MANY_OPEN_FILES = 4
  ERROR_ACCESS_DENIED = 5
  ERROR_INVALID_HANDLE = 6
  ERROR_ARENA_TRASHED = 7
  ERROR_NOT_ENOUGH_MEMORY = 8
  ERROR_INVALID_BLOCK = 9
  ERROR_BAD_ENVIRONMENT = 10
  ERROR_BAD_FORMAT = 11
  ERROR_INVALID_ACCESS = 12
  ERROR_INVALID_DATA = 13
  ERROR_OUTOFMEMORY = 14
  ERROR_INVALID_DRIVE = 15
  ERROR_CURRENT_DIRECTORY = 16
  ERROR_NOT_SAME_DEVICE = 17
  ERROR_NO_MORE_FILES = 18
  ERROR_WRITE_PROTECT = 19
  ERROR_BAD_UNIT = 20
  ERROR_NOT_READY = 21
  ERROR_BAD_COMMAND = 22
  ERROR_CRC = 23
  ERROR_BAD_LENGTH = 24
  ERROR_SEEK = 25
  ERROR_NOT_DOS_DISK = 26
  ERROR_SECTOR_NOT_FOUND = 27
  ERROR_OUT_OF_PAPER = 28
  ERROR_WRITE_FAULT = 29
  ERROR_READ_FAULT = 30
  ERROR_GEN_FAILURE = 31
  ERROR_SHARING_VIOLATION = 32
  ERROR_LOCK_VIOLATION = 33
  ERROR_WRONG_DISK = 34
  ERROR_SHARING_BUFFER_EXCEEDED = 36
  ERROR_HANDLE_EOF = 38
  ERROR_HANDLE_DISK_FULL = 39
  ERROR_NOT_SUPPORTED = 50
  ERROR_REM_NOT_LIST = 51
  ERROR_DUP_NAME = 52
  ERROR_BAD_NETPATH = 53
  ERROR_NETWORK_BUSY = 54
  ERROR_DEV_NOT_EXIST = 55
  ERROR_TOO_MANY_CMDS = 56
  ERROR_ADAP_HDW_ERR = 57
  ERROR_BAD_NET_RESP = 58
  ERROR_UNEXP_NET_ERR = 59
  ERROR_BAD_REM_ADAP = 60
  ERROR_PRINTQ_FULL = 61
  ERROR_NO_SPOOL_SPACE = 62
  ERROR_PRINT_CANCELLED = 63
  ERROR_NETNAME_DELETED = 64
  ERROR_NETWORK_ACCESS_DENIED = 65
  ERROR_BAD_DEV_TYPE = 66
  ERROR_BAD_NET_NAME = 67
  ERROR_TOO_MANY_NAMES = 68
  ERROR_TOO_MANY_SESS = 69
  ERROR_SHARING_PAUSED = 70
  ERROR_REQ_NOT_ACCEP = 71
  ERROR_REDIR_PAUSED = 72
  ERROR_FILE_EXISTS = 80
  ERROR_CANNOT_MAKE = 82
  ERROR_FAIL_I24 = 83
  ERROR_OUT_OF_STRUCTURES = 84
  ERROR_ALREADY_ASSIGNED = 85
  ERROR_INVALID_PASSWORD = 86
  ERROR_INVALID_PARAMETER = 87
  ERROR_NET_WRITE_FAULT = 88
  ERROR_NO_PROC_SLOTS = 89
  ERROR_TOO_MANY_SEMAPHORES = 100
  ERROR_EXCL_SEM_ALREADY_OWNED = 101
  ERROR_SEM_IS_SET = 102
  ERROR_TOO_MANY_SEM_REQUESTS = 103
  ERROR_INVALID_AT_INTERRUPT_TIME = 104
  ERROR_SEM_OWNER_DIED = 105
  ERROR_SEM_USER_LIMIT = 106
  ERROR_DISK_CHANGE = 107
  ERROR_DRIVE_LOCKED = 108
  ERROR_BROKEN_PIPE = 109
  ERROR_OPEN_FAILED = 110
  ERROR_BUFFER_OVERFLOW = 111
  ERROR_DISK_FULL = 112
  ERROR_NO_MORE_SEARCH_HANDLES = 113
  ERROR_INVALID_TARGET_HANDLE = 114
  ERROR_INVALID_CATEGORY = 117
  ERROR_INVALID_VERIFY_SWITCH = 118
  ERROR_BAD_DRIVER_LEVEL = 119
  ERROR_CALL_NOT_IMPLEMENTED = 120
  ERROR_SEM_TIMEOUT = 121
  ERROR_INSUFFICIENT_BUFFER = 122
  ERROR_INVALID_NAME = 123
  ERROR_INVALID_LEVEL = 124
  ERROR_NO_VOLUME_LABEL = 125
  ERROR_MOD_NOT_FOUND = 126
  ERROR_PROC_NOT_FOUND = 127
  ERROR_WAIT_NO_CHILDREN = 128
  ERROR_CHILD_NOT_COMPLETE = 129
  ERROR_DIRECT_ACCESS_HANDLE = 130
  ERROR_NEGATIVE_SEEK = 131
  ERROR_SEEK_ON_DEVICE = 132
  ERROR_IS_JOIN_TARGET = 133
  ERROR_IS_JOINED = 134
  ERROR_IS_SUBSTED = 135
  ERROR_NOT_JOINED = 136
  ERROR_NOT_SUBSTED = 137
  ERROR_JOIN_TO_JOIN = 138
  ERROR_SUBST_TO_SUBST = 139
  ERROR_JOIN_TO_SUBST = 140
  ERROR_SUBST_TO_JOIN = 141
  ERROR_BUSY_DRIVE = 142
  ERROR_SAME_DRIVE = 143
  ERROR_DIR_NOT_ROOT = 144
  ERROR_DIR_NOT_EMPTY = 145
  ERROR_IS_SUBST_PATH = 146
  ERROR_IS_JOIN_PATH = 147
  ERROR_PATH_BUSY = 148
  ERROR_IS_SUBST_TARGET = 149
  ERROR_SYSTEM_TRACE = 150
  ERROR_INVALID_EVENT_COUNT = 151
  ERROR_TOO_MANY_MUXWAITERS = 152
  ERROR_INVALID_LIST_FORMAT = 153
  ERROR_LABEL_TOO_LONG = 154
  ERROR_TOO_MANY_TCBS = 155
  ERROR_SIGNAL_REFUSED = 156
  ERROR_DISCARDED = 157
  ERROR_NOT_LOCKED = 158
  ERROR_BAD_THREADID_ADDR = 159
  ERROR_BAD_ARGUMENTS = 160
  ERROR_BAD_PATHNAME = 161
  ERROR_SIGNAL_PENDING = 162
  ERROR_MAX_THRDS_REACHED = 164
  ERROR_LOCK_FAILED = 167
  ERROR_BUSY = 170
  ERROR_DEVICE_SUPPORT_IN_PROGRESS = 171
  ERROR_CANCEL_VIOLATION = 173
  ERROR_ATOMIC_LOCKS_NOT_SUPPORTED = 174
  ERROR_INVALID_SEGMENT_NUMBER = 180
  ERROR_INVALID_ORDINAL = 182
  ERROR_ALREADY_EXISTS = 183
  ERROR_INVALID_FLAG_NUMBER = 186
  ERROR_SEM_NOT_FOUND = 187
  ERROR_INVALID_STARTING_CODESEG = 188
  ERROR_INVALID_STACKSEG = 189
  ERROR_INVALID_MODULETYPE = 190
  ERROR_INVALID_EXE_SIGNATURE = 191
  ERROR_EXE_MARKED_INVALID = 192
  ERROR_BAD_EXE_FORMAT = 193
  ERROR_ITERATED_DATA_EXCEEDS_64k = 194
  ERROR_INVALID_MINALLOCSIZE = 195
  ERROR_DYNLINK_FROM_INVALID_RING = 196
  ERROR_IOPL_NOT_ENABLED = 197
  ERROR_INVALID_SEGDPL = 198
  ERROR_AUTODATASEG_EXCEEDS_64k = 199
  ERROR_RING2SEG_MUST_BE_MOVABLE = 200
  ERROR_RELOC_CHAIN_XEEDS_SEGLIM = 201
  ERROR_INFLOOP_IN_RELOC_CHAIN = 202
  ERROR_ENVVAR_NOT_FOUND = 203
  ERROR_NO_SIGNAL_SENT = 205
  ERROR_FILENAME_EXCED_RANGE = 206
  ERROR_RING2_STACK_IN_USE = 207
  ERROR_META_EXPANSION_TOO_LONG = 208
  ERROR_INVALID_SIGNAL_NUMBER = 209
  ERROR_THREAD_1_INACTIVE = 210
  ERROR_LOCKED = 212
  ERROR_TOO_MANY_MODULES = 214
  ERROR_NESTING_NOT_ALLOWED = 215
  ERROR_EXE_MACHINE_TYPE_MISMATCH = 216
  ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY = 217
  ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY = 218
  ERROR_FILE_CHECKED_OUT = 220
  ERROR_CHECKOUT_REQUIRED = 221
  ERROR_BAD_FILE_TYPE = 222
  ERROR_FILE_TOO_LARGE = 223
  ERROR_FORMS_AUTH_REQUIRED = 224
  ERROR_VIRUS_INFECTED = 225
  ERROR_VIRUS_DELETED = 226
  ERROR_PIPE_LOCAL = 229
  ERROR_BAD_PIPE = 230
  ERROR_PIPE_BUSY = 231
  ERROR_NO_DATA = 232
  ERROR_PIPE_NOT_CONNECTED = 233
  ERROR_MORE_DATA = 234
  ERROR_NO_WORK_DONE = 235
  ERROR_VC_DISCONNECTED = 240
  ERROR_INVALID_EA_NAME = 254
  ERROR_EA_LIST_INCONSISTENT = 255
  WAIT_TIMEOUT = 258
  ERROR_NO_MORE_ITEMS = 259
  ERROR_CANNOT_COPY = 266
  ERROR_DIRECTORY = 267
  ERROR_EAS_DIDNT_FIT = 275
  ERROR_EA_FILE_CORRUPT = 276
  ERROR_EA_TABLE_FULL = 277
  ERROR_INVALID_EA_HANDLE = 278
  ERROR_EAS_NOT_SUPPORTED = 282
  ERROR_NOT_OWNER = 288
  ERROR_TOO_MANY_POSTS = 298
  ERROR_PARTIAL_COPY = 299
  ERROR_OPLOCK_NOT_GRANTED = 300
  ERROR_INVALID_OPLOCK_PROTOCOL = 301
  ERROR_DISK_TOO_FRAGMENTED = 302
  ERROR_DELETE_PENDING = 303
  ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING = 304
  ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME = 305
  ERROR_SECURITY_STREAM_IS_INCONSISTENT = 306
  ERROR_INVALID_LOCK_RANGE = 307
  ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT = 308
  ERROR_NOTIFICATION_GUID_ALREADY_DEFINED = 309
  ERROR_INVALID_EXCEPTION_HANDLER = 310
  ERROR_DUPLICATE_PRIVILEGES = 311
  ERROR_NO_RANGES_PROCESSED = 312
  ERROR_NOT_ALLOWED_ON_SYSTEM_FILE = 313
  ERROR_DISK_RESOURCES_EXHAUSTED = 314
  ERROR_INVALID_TOKEN = 315
  ERROR_DEVICE_FEATURE_NOT_SUPPORTED = 316
  ERROR_MR_MID_NOT_FOUND = 317
  ERROR_SCOPE_NOT_FOUND = 318
  ERROR_UNDEFINED_SCOPE = 319
  ERROR_INVALID_CAP = 320
  ERROR_DEVICE_UNREACHABLE = 321
  ERROR_DEVICE_NO_RESOURCES = 322
  ERROR_DATA_CHECKSUM_ERROR = 323
  ERROR_INTERMIXED_KERNEL_EA_OPERATION = 324
  ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED = 326
  ERROR_OFFSET_ALIGNMENT_VIOLATION = 327
  ERROR_INVALID_FIELD_IN_PARAMETER_LIST = 328
  ERROR_OPERATION_IN_PROGRESS = 329
  ERROR_BAD_DEVICE_PATH = 330
  ERROR_TOO_MANY_DESCRIPTORS = 331
  ERROR_SCRUB_DATA_DISABLED = 332
  ERROR_NOT_REDUNDANT_STORAGE = 333
  ERROR_RESIDENT_FILE_NOT_SUPPORTED = 334
  ERROR_COMPRESSED_FILE_NOT_SUPPORTED = 335
  ERROR_DIRECTORY_NOT_SUPPORTED = 336
  ERROR_NOT_READ_FROM_COPY = 337
  ERROR_FT_WRITE_FAILURE = 338
  ERROR_FT_DI_SCAN_REQUIRED = 339
  ERROR_INVALID_KERNEL_INFO_VERSION = 340
  ERROR_INVALID_PEP_INFO_VERSION = 341
  ERROR_OBJECT_NOT_EXTERNALLY_BACKED = 342
  ERROR_EXTERNAL_BACKING_PROVIDER_UNKNOWN = 343
  ERROR_COMPRESSION_NOT_BENEFICIAL = 344
  ERROR_STORAGE_TOPOLOGY_ID_MISMATCH = 345
  ERROR_BLOCKED_BY_PARENTAL_CONTROLS = 346
  ERROR_BLOCK_TOO_MANY_REFERENCES = 347
  ERROR_MARKED_TO_DISALLOW_WRITES = 348
  ERROR_ENCLAVE_FAILURE = 349
  ERROR_FAIL_NOACTION_REBOOT = 350
  ERROR_FAIL_SHUTDOWN = 351
  ERROR_FAIL_RESTART = 352
  ERROR_MAX_SESSIONS_REACHED = 353
  ERROR_NETWORK_ACCESS_DENIED_EDP = 354
  ERROR_DEVICE_HINT_NAME_BUFFER_TOO_SMALL = 355
  ERROR_EDP_POLICY_DENIES_OPERATION = 356
  ERROR_EDP_DPL_POLICY_CANT_BE_SATISFIED = 357
  ERROR_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT = 358
  ERROR_DEVICE_IN_MAINTENANCE = 359
  ERROR_NOT_SUPPORTED_ON_DAX = 360
  ERROR_DAX_MAPPING_EXISTS = 361
  ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING = 362
  ERROR_CLOUD_FILE_METADATA_CORRUPT = 363
  ERROR_CLOUD_FILE_METADATA_TOO_LARGE = 364
  ERROR_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE = 365
  ERROR_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH = 366
  ERROR_CHILD_PROCESS_BLOCKED = 367
  ERROR_STORAGE_LOST_DATA_PERSISTENCE = 368
  ERROR_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE = 369
  ERROR_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT = 370
  ERROR_FILE_SYSTEM_VIRTUALIZATION_BUSY = 371
  ERROR_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN = 372
  ERROR_GDI_HANDLE_LEAK = 373
  ERROR_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS = 374
  ERROR_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED = 375
  ERROR_NOT_A_CLOUD_FILE = 376
  ERROR_CLOUD_FILE_NOT_IN_SYNC = 377
  ERROR_CLOUD_FILE_ALREADY_CONNECTED = 378
  ERROR_CLOUD_FILE_NOT_SUPPORTED = 379
  ERROR_CLOUD_FILE_INVALID_REQUEST = 380
  ERROR_CLOUD_FILE_READ_ONLY_VOLUME = 381
  ERROR_CLOUD_FILE_CONNECTED_PROVIDER_ONLY = 382
  ERROR_CLOUD_FILE_VALIDATION_FAILED = 383
  ERROR_SMB1_NOT_AVAILABLE = 384
  ERROR_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION = 385
  ERROR_CLOUD_FILE_AUTHENTICATION_FAILED = 386
  ERROR_CLOUD_FILE_INSUFFICIENT_RESOURCES = 387
  ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE = 388
  ERROR_CLOUD_FILE_UNSUCCESSFUL = 389
  ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT = 390
  ERROR_CLOUD_FILE_IN_USE = 391
  ERROR_CLOUD_FILE_PINNED = 392
  ERROR_CLOUD_FILE_REQUEST_ABORTED = 393
  ERROR_CLOUD_FILE_PROPERTY_CORRUPT = 394
  ERROR_CLOUD_FILE_ACCESS_DENIED = 395
  ERROR_CLOUD_FILE_INCOMPATIBLE_HARDLINKS = 396
  ERROR_CLOUD_FILE_PROPERTY_LOCK_CONFLICT = 397
  ERROR_CLOUD_FILE_REQUEST_CANCELED = 398
  ERROR_EXTERNAL_SYSKEY_NOT_SUPPORTED = 399
  ERROR_THREAD_MODE_ALREADY_BACKGROUND = 400
  ERROR_THREAD_MODE_NOT_BACKGROUND = 401
  ERROR_PROCESS_MODE_ALREADY_BACKGROUND = 402
  ERROR_PROCESS_MODE_NOT_BACKGROUND = 403
  ERROR_CLOUD_FILE_PROVIDER_TERMINATED = 404
  ERROR_NOT_A_CLOUD_SYNC_ROOT = 405
  ERROR_FILE_PROTECTED_UNDER_DPL = 406
  ERROR_VOLUME_NOT_CLUSTER_ALIGNED = 407
  ERROR_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND = 408
  ERROR_APPX_FILE_NOT_ENCRYPTED = 409
  ERROR_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED = 410
  ERROR_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET = 411
  ERROR_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE = 412
  ERROR_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER = 413
  ERROR_LINUX_SUBSYSTEM_NOT_PRESENT = 414
  ERROR_FT_READ_FAILURE = 415
  ERROR_STORAGE_RESERVE_ID_INVALID = 416
  ERROR_STORAGE_RESERVE_DOES_NOT_EXIST = 417
  ERROR_STORAGE_RESERVE_ALREADY_EXISTS = 418
  ERROR_STORAGE_RESERVE_NOT_EMPTY = 419
  ERROR_NOT_A_DAX_VOLUME = 420
  ERROR_NOT_DAX_MAPPABLE = 421
  ERROR_TIME_SENSITIVE_THREAD = 422
  ERROR_DPL_NOT_SUPPORTED_FOR_USER = 423
  ERROR_CASE_DIFFERING_NAMES_IN_DIR = 424
  ERROR_FILE_NOT_SUPPORTED = 425
  ERROR_CLOUD_FILE_REQUEST_TIMEOUT = 426
  ERROR_NO_TASK_QUEUE = 427
  ERROR_SRC_SRV_DLL_LOAD_FAILED = 428
  ERROR_NOT_SUPPORTED_WITH_BTT = 429
  ERROR_ENCRYPTION_DISABLED = 430
  ERROR_ENCRYPTING_METADATA_DISALLOWED = 431
  ERROR_CANT_CLEAR_ENCRYPTION_FLAG = 432
  ERROR_NO_SUCH_DEVICE = 433
  ERROR_CLOUD_FILE_DEHYDRATION_DISALLOWED = 434
  ERROR_FILE_SNAP_IN_PROGRESS = 435
  ERROR_FILE_SNAP_USER_SECTION_NOT_SUPPORTED = 436
  ERROR_FILE_SNAP_MODIFY_NOT_SUPPORTED = 437
  ERROR_FILE_SNAP_IO_NOT_COORDINATED = 438
  ERROR_FILE_SNAP_UNEXPECTED_ERROR = 439
  ERROR_FILE_SNAP_INVALID_PARAMETER = 440
  ERROR_UNSATISFIED_DEPENDENCIES = 441
  ERROR_CASE_SENSITIVE_PATH = 442
  ERROR_UNEXPECTED_NTCACHEMANAGER_ERROR = 443
  ERROR_LINUX_SUBSYSTEM_UPDATE_REQUIRED = 444
  ERROR_DLP_POLICY_WARNS_AGAINST_OPERATION = 445
  ERROR_DLP_POLICY_DENIES_OPERATION = 446
  ERROR_SECURITY_DENIES_OPERATION = 447
  ERROR_UNTRUSTED_MOUNT_POINT = 448
  ERROR_DLP_POLICY_SILENTLY_FAIL = 449
  ERROR_CAPAUTHZ_NOT_DEVUNLOCKED = 450
  ERROR_CAPAUTHZ_CHANGE_TYPE = 451
  ERROR_CAPAUTHZ_NOT_PROVISIONED = 452
  ERROR_CAPAUTHZ_NOT_AUTHORIZED = 453
  ERROR_CAPAUTHZ_NO_POLICY = 454
  ERROR_CAPAUTHZ_DB_CORRUPTED = 455
  ERROR_CAPAUTHZ_SCCD_INVALID_CATALOG = 456
  ERROR_CAPAUTHZ_SCCD_NO_AUTH_ENTITY = 457
  ERROR_CAPAUTHZ_SCCD_PARSE_ERROR = 458
  ERROR_CAPAUTHZ_SCCD_DEV_MODE_REQUIRED = 459
  ERROR_CAPAUTHZ_SCCD_NO_CAPABILITY_MATCH = 460
  ERROR_CIMFS_IMAGE_CORRUPT = 470
  ERROR_CIMFS_IMAGE_VERSION_NOT_SUPPORTED = 471
  ERROR_STORAGE_STACK_ACCESS_DENIED = 472
  ERROR_INSUFFICIENT_VIRTUAL_ADDR_RESOURCES = 473
  ERROR_INDEX_OUT_OF_BOUNDS = 474
  ERROR_CLOUD_FILE_US_MESSAGE_TIMEOUT = 475
  ERROR_NOT_A_DEV_VOLUME = 476
  ERROR_FS_GUID_MISMATCH = 477
  ERROR_CANT_ATTACH_TO_DEV_VOLUME = 478
  ERROR_INVALID_CONFIG_VALUE = 479
  ERROR_PNP_QUERY_REMOVE_DEVICE_TIMEOUT = 480
  ERROR_PNP_QUERY_REMOVE_RELATED_DEVICE_TIMEOUT = 481
  ERROR_PNP_QUERY_REMOVE_UNRELATED_DEVICE_TIMEOUT = 482
  ERROR_DEVICE_HARDWARE_ERROR = 483
  ERROR_INVALID_ADDRESS = 487
  ERROR_HAS_SYSTEM_CRITICAL_FILES = 488
  ERROR_ENCRYPTED_FILE_NOT_SUPPORTED = 489
  ERROR_SPARSE_FILE_NOT_SUPPORTED = 490
  ERROR_PAGEFILE_NOT_SUPPORTED = 491
  ERROR_VOLUME_NOT_SUPPORTED = 492
  ERROR_NOT_SUPPORTED_WITH_BYPASSIO = 493
  ERROR_NO_BYPASSIO_DRIVER_SUPPORT = 494
  ERROR_NOT_SUPPORTED_WITH_ENCRYPTION = 495
  ERROR_NOT_SUPPORTED_WITH_COMPRESSION = 496
  ERROR_NOT_SUPPORTED_WITH_REPLICATION = 497
  ERROR_NOT_SUPPORTED_WITH_DEDUPLICATION = 498
  ERROR_NOT_SUPPORTED_WITH_AUDITING = 499
  ERROR_USER_PROFILE_LOAD = 500
  ERROR_SESSION_KEY_TOO_SHORT = 501
  ERROR_ACCESS_DENIED_APPDATA = 502
  ERROR_NOT_SUPPORTED_WITH_MONITORING = 503
  ERROR_NOT_SUPPORTED_WITH_SNAPSHOT = 504
  ERROR_NOT_SUPPORTED_WITH_VIRTUALIZATION = 505
  ERROR_BYPASSIO_FLT_NOT_SUPPORTED = 506
  ERROR_DEVICE_RESET_REQUIRED = 507
  ERROR_VOLUME_WRITE_ACCESS_DENIED = 508
  ERROR_NOT_SUPPORTED_WITH_CACHED_HANDLE = 509
  ERROR_FS_METADATA_INCONSISTENT = 510
  ERROR_BLOCK_WEAK_REFERENCE_INVALID = 511
  ERROR_BLOCK_SOURCE_WEAK_REFERENCE_INVALID = 512
  ERROR_BLOCK_TARGET_WEAK_REFERENCE_INVALID = 513
  ERROR_BLOCK_SHARED = 514
  ERROR_VOLUME_UPGRADE_NOT_NEEDED = 515
  ERROR_VOLUME_UPGRADE_PENDING = 516
  ERROR_VOLUME_UPGRADE_DISABLED = 517
  ERROR_VOLUME_UPGRADE_DISABLED_TILL_OS_DOWNGRADE_EXPIRED = 518
  ERROR_ARITHMETIC_OVERFLOW = 534
  ERROR_PIPE_CONNECTED = 535
  ERROR_PIPE_LISTENING = 536
  ERROR_VERIFIER_STOP = 537
  ERROR_ABIOS_ERROR = 538
  ERROR_WX86_WARNING = 539
  ERROR_WX86_ERROR = 540
  ERROR_TIMER_NOT_CANCELED = 541
  ERROR_UNWIND = 542
  ERROR_BAD_STACK = 543
  ERROR_INVALID_UNWIND_TARGET = 544
  ERROR_INVALID_PORT_ATTRIBUTES = 545
  ERROR_PORT_MESSAGE_TOO_LONG = 546
  ERROR_INVALID_QUOTA_LOWER = 547
  ERROR_DEVICE_ALREADY_ATTACHED = 548
  ERROR_INSTRUCTION_MISALIGNMENT = 549
  ERROR_PROFILING_NOT_STARTED = 550
  ERROR_PROFILING_NOT_STOPPED = 551
  ERROR_COULD_NOT_INTERPRET = 552
  ERROR_PROFILING_AT_LIMIT = 553
  ERROR_CANT_WAIT = 554
  ERROR_CANT_TERMINATE_SELF = 555
  ERROR_UNEXPECTED_MM_CREATE_ERR = 556
  ERROR_UNEXPECTED_MM_MAP_ERROR = 557
  ERROR_UNEXPECTED_MM_EXTEND_ERR = 558
  ERROR_BAD_FUNCTION_TABLE = 559
  ERROR_NO_GUID_TRANSLATION = 560
  ERROR_INVALID_LDT_SIZE = 561
  ERROR_INVALID_LDT_OFFSET = 563
  ERROR_INVALID_LDT_DESCRIPTOR = 564
  ERROR_TOO_MANY_THREADS = 565
  ERROR_THREAD_NOT_IN_PROCESS = 566
  ERROR_PAGEFILE_QUOTA_EXCEEDED = 567
  ERROR_LOGON_SERVER_CONFLICT = 568
  ERROR_SYNCHRONIZATION_REQUIRED = 569
  ERROR_NET_OPEN_FAILED = 570
  ERROR_IO_PRIVILEGE_FAILED = 571
  ERROR_CONTROL_C_EXIT = 572
  ERROR_MISSING_SYSTEMFILE = 573
  ERROR_UNHANDLED_EXCEPTION = 574
  ERROR_APP_INIT_FAILURE = 575
  ERROR_PAGEFILE_CREATE_FAILED = 576
  ERROR_INVALID_IMAGE_HASH = 577
  ERROR_NO_PAGEFILE = 578
  ERROR_ILLEGAL_FLOAT_CONTEXT = 579
  ERROR_NO_EVENT_PAIR = 580
  ERROR_DOMAIN_CTRLR_CONFIG_ERROR = 581
  ERROR_ILLEGAL_CHARACTER = 582
  ERROR_UNDEFINED_CHARACTER = 583
  ERROR_FLOPPY_VOLUME = 584
  ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT = 585
  ERROR_BACKUP_CONTROLLER = 586
  ERROR_MUTANT_LIMIT_EXCEEDED = 587
  ERROR_FS_DRIVER_REQUIRED = 588
  ERROR_CANNOT_LOAD_REGISTRY_FILE = 589
  ERROR_DEBUG_ATTACH_FAILED = 590
  ERROR_SYSTEM_PROCESS_TERMINATED = 591
  ERROR_DATA_NOT_ACCEPTED = 592
  ERROR_VDM_HARD_ERROR = 593
  ERROR_DRIVER_CANCEL_TIMEOUT = 594
  ERROR_REPLY_MESSAGE_MISMATCH = 595
  ERROR_LOST_WRITEBEHIND_DATA = 596
  ERROR_CLIENT_SERVER_PARAMETERS_INVALID = 597
  ERROR_NOT_TINY_STREAM = 598
  ERROR_STACK_OVERFLOW_READ = 599
  ERROR_CONVERT_TO_LARGE = 600
  ERROR_FOUND_OUT_OF_SCOPE = 601
  ERROR_ALLOCATE_BUCKET = 602
  ERROR_MARSHALL_OVERFLOW = 603
  ERROR_INVALID_VARIANT = 604
  ERROR_BAD_COMPRESSION_BUFFER = 605
  ERROR_AUDIT_FAILED = 606
  ERROR_TIMER_RESOLUTION_NOT_SET = 607
  ERROR_INSUFFICIENT_LOGON_INFO = 608
  ERROR_BAD_DLL_ENTRYPOINT = 609
  ERROR_BAD_SERVICE_ENTRYPOINT = 610
  ERROR_IP_ADDRESS_CONFLICT1 = 611
  ERROR_IP_ADDRESS_CONFLICT2 = 612
  ERROR_REGISTRY_QUOTA_LIMIT = 613
  ERROR_NO_CALLBACK_ACTIVE = 614
  ERROR_PWD_TOO_SHORT = 615
  ERROR_PWD_TOO_RECENT = 616
  ERROR_PWD_HISTORY_CONFLICT = 617
  ERROR_UNSUPPORTED_COMPRESSION = 618
  ERROR_INVALID_HW_PROFILE = 619
  ERROR_INVALID_PLUGPLAY_DEVICE_PATH = 620
  ERROR_QUOTA_LIST_INCONSISTENT = 621
  ERROR_EVALUATION_EXPIRATION = 622
  ERROR_ILLEGAL_DLL_RELOCATION = 623
  ERROR_DLL_INIT_FAILED_LOGOFF = 624
  ERROR_VALIDATE_CONTINUE = 625
  ERROR_NO_MORE_MATCHES = 626
  ERROR_RANGE_LIST_CONFLICT = 627
  ERROR_SERVER_SID_MISMATCH = 628
  ERROR_CANT_ENABLE_DENY_ONLY = 629
  ERROR_FLOAT_MULTIPLE_FAULTS = 630
  ERROR_FLOAT_MULTIPLE_TRAPS = 631
  ERROR_NOINTERFACE = 632
  ERROR_DRIVER_FAILED_SLEEP = 633
  ERROR_CORRUPT_SYSTEM_FILE = 634
  ERROR_COMMITMENT_MINIMUM = 635
  ERROR_PNP_RESTART_ENUMERATION = 636
  ERROR_SYSTEM_IMAGE_BAD_SIGNATURE = 637
  ERROR_PNP_REBOOT_REQUIRED = 638
  ERROR_INSUFFICIENT_POWER = 639
  ERROR_MULTIPLE_FAULT_VIOLATION = 640
  ERROR_SYSTEM_SHUTDOWN = 641
  ERROR_PORT_NOT_SET = 642
  ERROR_DS_VERSION_CHECK_FAILURE = 643
  ERROR_RANGE_NOT_FOUND = 644
  ERROR_NOT_SAFE_MODE_DRIVER = 646
  ERROR_FAILED_DRIVER_ENTRY = 647
  ERROR_DEVICE_ENUMERATION_ERROR = 648
  ERROR_MOUNT_POINT_NOT_RESOLVED = 649
  ERROR_INVALID_DEVICE_OBJECT_PARAMETER = 650
  ERROR_MCA_OCCURED = 651
  ERROR_DRIVER_DATABASE_ERROR = 652
  ERROR_SYSTEM_HIVE_TOO_LARGE = 653
  ERROR_DRIVER_FAILED_PRIOR_UNLOAD = 654
  ERROR_VOLSNAP_PREPARE_HIBERNATE = 655
  ERROR_HIBERNATION_FAILURE = 656
  ERROR_PWD_TOO_LONG = 657
  ERROR_FILE_SYSTEM_LIMITATION = 665
  ERROR_ASSERTION_FAILURE = 668
  ERROR_ACPI_ERROR = 669
  ERROR_WOW_ASSERTION = 670
  ERROR_PNP_BAD_MPS_TABLE = 671
  ERROR_PNP_TRANSLATION_FAILED = 672
  ERROR_PNP_IRQ_TRANSLATION_FAILED = 673
  ERROR_PNP_INVALID_ID = 674
  ERROR_WAKE_SYSTEM_DEBUGGER = 675
  ERROR_HANDLES_CLOSED = 676
  ERROR_EXTRANEOUS_INFORMATION = 677
  ERROR_RXACT_COMMIT_NECESSARY = 678
  ERROR_MEDIA_CHECK = 679
  ERROR_GUID_SUBSTITUTION_MADE = 680
  ERROR_STOPPED_ON_SYMLINK = 681
  ERROR_LONGJUMP = 682
  ERROR_PLUGPLAY_QUERY_VETOED = 683
  ERROR_UNWIND_CONSOLIDATE = 684
  ERROR_REGISTRY_HIVE_RECOVERED = 685
  ERROR_DLL_MIGHT_BE_INSECURE = 686
  ERROR_DLL_MIGHT_BE_INCOMPATIBLE = 687
  ERROR_DBG_EXCEPTION_NOT_HANDLED = 688
  ERROR_DBG_REPLY_LATER = 689
  ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE = 690
  ERROR_DBG_TERMINATE_THREAD = 691
  ERROR_DBG_TERMINATE_PROCESS = 692
  ERROR_DBG_CONTROL_C = 693
  ERROR_DBG_PRINTEXCEPTION_C = 694
  ERROR_DBG_RIPEXCEPTION = 695
  ERROR_DBG_CONTROL_BREAK = 696
  ERROR_DBG_COMMAND_EXCEPTION = 697
  ERROR_OBJECT_NAME_EXISTS = 698
  ERROR_THREAD_WAS_SUSPENDED = 699
  ERROR_IMAGE_NOT_AT_BASE = 700
  ERROR_RXACT_STATE_CREATED = 701
  ERROR_SEGMENT_NOTIFICATION = 702
  ERROR_BAD_CURRENT_DIRECTORY = 703
  ERROR_FT_READ_RECOVERY_FROM_BACKUP = 704
  ERROR_FT_WRITE_RECOVERY = 705
  ERROR_IMAGE_MACHINE_TYPE_MISMATCH = 706
  ERROR_RECEIVE_PARTIAL = 707
  ERROR_RECEIVE_EXPEDITED = 708
  ERROR_RECEIVE_PARTIAL_EXPEDITED = 709
  ERROR_EVENT_DONE = 710
  ERROR_EVENT_PENDING = 711
  ERROR_CHECKING_FILE_SYSTEM = 712
  ERROR_FATAL_APP_EXIT = 713
  ERROR_PREDEFINED_HANDLE = 714
  ERROR_WAS_UNLOCKED = 715
  ERROR_SERVICE_NOTIFICATION = 716
  ERROR_WAS_LOCKED = 717
  ERROR_LOG_HARD_ERROR = 718
  ERROR_ALREADY_WIN32 = 719
  ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE = 720
  ERROR_NO_YIELD_PERFORMED = 721
  ERROR_TIMER_RESUME_IGNORED = 722
  ERROR_ARBITRATION_UNHANDLED = 723
  ERROR_CARDBUS_NOT_SUPPORTED = 724
  ERROR_MP_PROCESSOR_MISMATCH = 725
  ERROR_HIBERNATED = 726
  ERROR_RESUME_HIBERNATION = 727
  ERROR_FIRMWARE_UPDATED = 728
  ERROR_DRIVERS_LEAKING_LOCKED_PAGES = 729
  ERROR_WAKE_SYSTEM = 730
  ERROR_WAIT_1 = 731
  ERROR_WAIT_2 = 732
  ERROR_WAIT_3 = 733
  ERROR_WAIT_63 = 734
  ERROR_ABANDONED_WAIT_0 = 735
  ERROR_ABANDONED_WAIT_63 = 736
  ERROR_USER_APC = 737
  ERROR_KERNEL_APC = 738
  ERROR_ALERTED = 739
  ERROR_ELEVATION_REQUIRED = 740
  ERROR_REPARSE = 741
  ERROR_OPLOCK_BREAK_IN_PROGRESS = 742
  ERROR_VOLUME_MOUNTED = 743
  ERROR_RXACT_COMMITTED = 744
  ERROR_NOTIFY_CLEANUP = 745
  ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED = 746
  ERROR_PAGE_FAULT_TRANSITION = 747
  ERROR_PAGE_FAULT_DEMAND_ZERO = 748
  ERROR_PAGE_FAULT_COPY_ON_WRITE = 749
  ERROR_PAGE_FAULT_GUARD_PAGE = 750
  ERROR_PAGE_FAULT_PAGING_FILE = 751
  ERROR_CACHE_PAGE_LOCKED = 752
  ERROR_CRASH_DUMP = 753
  ERROR_BUFFER_ALL_ZEROS = 754
  ERROR_REPARSE_OBJECT = 755
  ERROR_RESOURCE_REQUIREMENTS_CHANGED = 756
  ERROR_TRANSLATION_COMPLETE = 757
  ERROR_NOTHING_TO_TERMINATE = 758
  ERROR_PROCESS_NOT_IN_JOB = 759
  ERROR_PROCESS_IN_JOB = 760
  ERROR_VOLSNAP_HIBERNATE_READY = 761
  ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY = 762
  ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED = 763
  ERROR_INTERRUPT_STILL_CONNECTED = 764
  ERROR_WAIT_FOR_OPLOCK = 765
  ERROR_DBG_EXCEPTION_HANDLED = 766
  ERROR_DBG_CONTINUE = 767
  ERROR_CALLBACK_POP_STACK = 768
  ERROR_COMPRESSION_DISABLED = 769
  ERROR_CANTFETCHBACKWARDS = 770
  ERROR_CANTSCROLLBACKWARDS = 771
  ERROR_ROWSNOTRELEASED = 772
  ERROR_BAD_ACCESSOR_FLAGS = 773
  ERROR_ERRORS_ENCOUNTERED = 774
  ERROR_NOT_CAPABLE = 775
  ERROR_REQUEST_OUT_OF_SEQUENCE = 776
  ERROR_VERSION_PARSE_ERROR = 777
  ERROR_BADSTARTPOSITION = 778
  ERROR_MEMORY_HARDWARE = 779
  ERROR_DISK_REPAIR_DISABLED = 780
  ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE = 781
  ERROR_SYSTEM_POWERSTATE_TRANSITION = 782
  ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION = 783
  ERROR_MCA_EXCEPTION = 784
  ERROR_ACCESS_AUDIT_BY_POLICY = 785
  ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY = 786
  ERROR_ABANDON_HIBERFILE = 787
  ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED = 788
  ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR = 789
  ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR = 790
  ERROR_BAD_MCFG_TABLE = 791
  ERROR_DISK_REPAIR_REDIRECTED = 792
  ERROR_DISK_REPAIR_UNSUCCESSFUL = 793
  ERROR_CORRUPT_LOG_OVERFULL = 794
  ERROR_CORRUPT_LOG_CORRUPTED = 795
  ERROR_CORRUPT_LOG_UNAVAILABLE = 796
  ERROR_CORRUPT_LOG_DELETED_FULL = 797
  ERROR_CORRUPT_LOG_CLEARED = 798
  ERROR_ORPHAN_NAME_EXHAUSTED = 799
  ERROR_OPLOCK_SWITCHED_TO_NEW_HANDLE = 800
  ERROR_CANNOT_GRANT_REQUESTED_OPLOCK = 801
  ERROR_CANNOT_BREAK_OPLOCK = 802
  ERROR_OPLOCK_HANDLE_CLOSED = 803
  ERROR_NO_ACE_CONDITION = 804
  ERROR_INVALID_ACE_CONDITION = 805
  ERROR_FILE_HANDLE_REVOKED = 806
  ERROR_IMAGE_AT_DIFFERENT_BASE = 807
  ERROR_ENCRYPTED_IO_NOT_POSSIBLE = 808
  ERROR_FILE_METADATA_OPTIMIZATION_IN_PROGRESS = 809
  ERROR_QUOTA_ACTIVITY = 810
  ERROR_HANDLE_REVOKED = 811
  ERROR_CALLBACK_INVOKE_INLINE = 812
  ERROR_CPU_SET_INVALID = 813
  ERROR_ENCLAVE_NOT_TERMINATED = 814
  ERROR_ENCLAVE_VIOLATION = 815
  ERROR_SERVER_TRANSPORT_CONFLICT = 816
  ERROR_CERTIFICATE_VALIDATION_PREFERENCE_CONFLICT = 817
  ERROR_FT_READ_FROM_COPY_FAILURE = 818
  ERROR_SECTION_DIRECT_MAP_ONLY = 819
  ERROR_EA_ACCESS_DENIED = 994
  ERROR_OPERATION_ABORTED = 995
  ERROR_IO_INCOMPLETE = 996
  ERROR_IO_PENDING = 997
  ERROR_NOACCESS = 998
  ERROR_SWAPERROR = 999
  ERROR_STACK_OVERFLOW = 1001
  ERROR_INVALID_MESSAGE = 1002
  ERROR_CAN_NOT_COMPLETE = 1003
  ERROR_INVALID_FLAGS = 1004
  ERROR_UNRECOGNIZED_VOLUME = 1005
  ERROR_FILE_INVALID = 1006
  ERROR_FULLSCREEN_MODE = 1007
  ERROR_NO_TOKEN = 1008
  ERROR_BADDB = 1009
  ERROR_BADKEY = 1010
  ERROR_CANTOPEN = 1011
  ERROR_CANTREAD = 1012
  ERROR_CANTWRITE = 1013
  ERROR_REGISTRY_RECOVERED = 1014
  ERROR_REGISTRY_CORRUPT = 1015
  ERROR_REGISTRY_IO_FAILED = 1016
  ERROR_NOT_REGISTRY_FILE = 1017
  ERROR_KEY_DELETED = 1018
  ERROR_NO_LOG_SPACE = 1019
  ERROR_KEY_HAS_CHILDREN = 1020
  ERROR_CHILD_MUST_BE_VOLATILE = 1021
  ERROR_NOTIFY_ENUM_DIR = 1022
  ERROR_DEPENDENT_SERVICES_RUNNING = 1051
  ERROR_INVALID_SERVICE_CONTROL = 1052
  ERROR_SERVICE_REQUEST_TIMEOUT = 1053
  ERROR_SERVICE_NO_THREAD = 1054
  ERROR_SERVICE_DATABASE_LOCKED = 1055
  ERROR_SERVICE_ALREADY_RUNNING = 1056
  ERROR_INVALID_SERVICE_ACCOUNT = 1057
  ERROR_SERVICE_DISABLED = 1058
  ERROR_CIRCULAR_DEPENDENCY = 1059
  ERROR_SERVICE_DOES_NOT_EXIST = 1060
  ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061
  ERROR_SERVICE_NOT_ACTIVE = 1062
  ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
  ERROR_EXCEPTION_IN_SERVICE = 1064
  ERROR_DATABASE_DOES_NOT_EXIST = 1065
  ERROR_SERVICE_SPECIFIC_ERROR = 1066
  ERROR_PROCESS_ABORTED = 1067
  ERROR_SERVICE_DEPENDENCY_FAIL = 1068
  ERROR_SERVICE_LOGON_FAILED = 1069
  ERROR_SERVICE_START_HANG = 1070
  ERROR_INVALID_SERVICE_LOCK = 1071
  ERROR_SERVICE_MARKED_FOR_DELETE = 1072
  ERROR_SERVICE_EXISTS = 1073
  ERROR_ALREADY_RUNNING_LKG = 1074
  ERROR_SERVICE_DEPENDENCY_DELETED = 1075
  ERROR_BOOT_ALREADY_ACCEPTED = 1076
  ERROR_SERVICE_NEVER_STARTED = 1077
  ERROR_DUPLICATE_SERVICE_NAME = 1078
  ERROR_DIFFERENT_SERVICE_ACCOUNT = 1079
  ERROR_CANNOT_DETECT_DRIVER_FAILURE = 1080
  ERROR_CANNOT_DETECT_PROCESS_ABORT = 1081
  ERROR_NO_RECOVERY_PROGRAM = 1082
  ERROR_SERVICE_NOT_IN_EXE = 1083
  ERROR_NOT_SAFEBOOT_SERVICE = 1084
  ERROR_END_OF_MEDIA = 1100
  ERROR_FILEMARK_DETECTED = 1101
  ERROR_BEGINNING_OF_MEDIA = 1102
  ERROR_SETMARK_DETECTED = 1103
  ERROR_NO_DATA_DETECTED = 1104
  ERROR_PARTITION_FAILURE = 1105
  ERROR_INVALID_BLOCK_LENGTH = 1106
  ERROR_DEVICE_NOT_PARTITIONED = 1107
  ERROR_UNABLE_TO_LOCK_MEDIA = 1108
  ERROR_UNABLE_TO_UNLOAD_MEDIA = 1109
  ERROR_MEDIA_CHANGED = 1110
  ERROR_BUS_RESET = 1111
  ERROR_NO_MEDIA_IN_DRIVE = 1112
  ERROR_NO_UNICODE_TRANSLATION = 1113
  ERROR_DLL_INIT_FAILED = 1114
  ERROR_SHUTDOWN_IN_PROGRESS = 1115
  ERROR_NO_SHUTDOWN_IN_PROGRESS = 1116
  ERROR_IO_DEVICE = 1117
  ERROR_SERIAL_NO_DEVICE = 1118
  ERROR_IRQ_BUSY = 1119
  ERROR_MORE_WRITES = 1120
  ERROR_COUNTER_TIMEOUT = 1121
  ERROR_FLOPPY_ID_MARK_NOT_FOUND = 1122
  ERROR_FLOPPY_WRONG_CYLINDER = 1123
  ERROR_FLOPPY_UNKNOWN_ERROR = 1124
  ERROR_FLOPPY_BAD_REGISTERS = 1125
  ERROR_DISK_RECALIBRATE_FAILED = 1126
  ERROR_DISK_OPERATION_FAILED = 1127
  ERROR_DISK_RESET_FAILED = 1128
  ERROR_EOM_OVERFLOW = 1129
  ERROR_NOT_ENOUGH_SERVER_MEMORY = 1130
  ERROR_POSSIBLE_DEADLOCK = 1131
  ERROR_MAPPED_ALIGNMENT = 1132
  ERROR_SET_POWER_STATE_VETOED = 1140
  ERROR_SET_POWER_STATE_FAILED = 1141
  ERROR_TOO_MANY_LINKS = 1142
  ERROR_OLD_WIN_VERSION = 1150
  ERROR_APP_WRONG_OS = 1151
  ERROR_SINGLE_INSTANCE_APP = 1152
  ERROR_RMODE_APP = 1153
  ERROR_INVALID_DLL = 1154
  ERROR_NO_ASSOCIATION = 1155
  ERROR_DDE_FAIL = 1156
  ERROR_DLL_NOT_FOUND = 1157
  ERROR_NO_MORE_USER_HANDLES = 1158
  ERROR_MESSAGE_SYNC_ONLY = 1159
  ERROR_SOURCE_ELEMENT_EMPTY = 1160
  ERROR_DESTINATION_ELEMENT_FULL = 1161
  ERROR_ILLEGAL_ELEMENT_ADDRESS = 1162
  ERROR_MAGAZINE_NOT_PRESENT = 1163
  ERROR_DEVICE_REINITIALIZATION_NEEDED = 1164
  ERROR_DEVICE_REQUIRES_CLEANING = 1165
  ERROR_DEVICE_DOOR_OPEN = 1166
  ERROR_DEVICE_NOT_CONNECTED = 1167
  ERROR_NOT_FOUND = 1168
  ERROR_NO_MATCH = 1169
  ERROR_SET_NOT_FOUND = 1170
  ERROR_POINT_NOT_FOUND = 1171
  ERROR_NO_TRACKING_SERVICE = 1172
  ERROR_NO_VOLUME_ID = 1173
  ERROR_UNABLE_TO_REMOVE_REPLACED = 1175
  ERROR_UNABLE_TO_MOVE_REPLACEMENT = 1176
  ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 = 1177
  ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178
  ERROR_JOURNAL_NOT_ACTIVE = 1179
  ERROR_POTENTIAL_FILE_FOUND = 1180
  ERROR_JOURNAL_ENTRY_DELETED = 1181
  ERROR_PARTITION_TERMINATING = 1184
  ERROR_SHUTDOWN_IS_SCHEDULED = 1190
  ERROR_SHUTDOWN_USERS_LOGGED_ON = 1191
  ERROR_SHUTDOWN_DISKS_NOT_IN_MAINTENANCE_MODE = 1192
  ERROR_BAD_DEVICE = 1200
  ERROR_CONNECTION_UNAVAIL = 1201
  ERROR_DEVICE_ALREADY_REMEMBERED = 1202
  ERROR_NO_NET_OR_BAD_PATH = 1203
  ERROR_BAD_PROVIDER = 1204
  ERROR_CANNOT_OPEN_PROFILE = 1205
  ERROR_BAD_PROFILE = 1206
  ERROR_NOT_CONTAINER = 1207
  ERROR_EXTENDED_ERROR = 1208
  ERROR_INVALID_GROUPNAME = 1209
  ERROR_INVALID_COMPUTERNAME = 1210
  ERROR_INVALID_EVENTNAME = 1211
  ERROR_INVALID_DOMAINNAME = 1212
  ERROR_INVALID_SERVICENAME = 1213
  ERROR_INVALID_NETNAME = 1214
  ERROR_INVALID_SHARENAME = 1215
  ERROR_INVALID_PASSWORDNAME = 1216
  ERROR_INVALID_MESSAGENAME = 1217
  ERROR_INVALID_MESSAGEDEST = 1218
  ERROR_SESSION_CREDENTIAL_CONFLICT = 1219
  ERROR_REMOTE_SESSION_LIMIT_EXCEEDED = 1220
  ERROR_DUP_DOMAINNAME = 1221
  ERROR_NO_NETWORK = 1222
  ERROR_CANCELLED = 1223
  ERROR_USER_MAPPED_FILE = 1224
  ERROR_CONNECTION_REFUSED = 1225
  ERROR_GRACEFUL_DISCONNECT = 1226
  ERROR_ADDRESS_ALREADY_ASSOCIATED = 1227
  ERROR_ADDRESS_NOT_ASSOCIATED = 1228
  ERROR_CONNECTION_INVALID = 1229
  ERROR_CONNECTION_ACTIVE = 1230
  ERROR_NETWORK_UNREACHABLE = 1231
  ERROR_HOST_UNREACHABLE = 1232
  ERROR_PROTOCOL_UNREACHABLE = 1233
  ERROR_PORT_UNREACHABLE = 1234
  ERROR_REQUEST_ABORTED = 1235
  ERROR_CONNECTION_ABORTED = 1236
  ERROR_RETRY = 1237
  ERROR_CONNECTION_COUNT_LIMIT = 1238
  ERROR_LOGIN_TIME_RESTRICTION = 1239
  ERROR_LOGIN_WKSTA_RESTRICTION = 1240
  ERROR_INCORRECT_ADDRESS = 1241
  ERROR_ALREADY_REGISTERED = 1242
  ERROR_SERVICE_NOT_FOUND = 1243
  ERROR_NOT_AUTHENTICATED = 1244
  ERROR_NOT_LOGGED_ON = 1245
  ERROR_CONTINUE = 1246
  ERROR_ALREADY_INITIALIZED = 1247
  ERROR_NO_MORE_DEVICES = 1248
  ERROR_NO_SUCH_SITE = 1249
  ERROR_DOMAIN_CONTROLLER_EXISTS = 1250
  ERROR_ONLY_IF_CONNECTED = 1251
  ERROR_OVERRIDE_NOCHANGES = 1252
  ERROR_BAD_USER_PROFILE = 1253
  ERROR_NOT_SUPPORTED_ON_SBS = 1254
  ERROR_SERVER_SHUTDOWN_IN_PROGRESS = 1255
  ERROR_HOST_DOWN = 1256
  ERROR_NON_ACCOUNT_SID = 1257
  ERROR_NON_DOMAIN_SID = 1258
  ERROR_APPHELP_BLOCK = 1259
  ERROR_ACCESS_DISABLED_BY_POLICY = 1260
  ERROR_REG_NAT_CONSUMPTION = 1261
  ERROR_CSCSHARE_OFFLINE = 1262
  ERROR_PKINIT_FAILURE = 1263
  ERROR_SMARTCARD_SUBSYSTEM_FAILURE = 1264
  ERROR_DOWNGRADE_DETECTED = 1265
  ERROR_MACHINE_LOCKED = 1271
  ERROR_SMB_GUEST_LOGON_BLOCKED = 1272
  ERROR_CALLBACK_SUPPLIED_INVALID_DATA = 1273
  ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED = 1274
  ERROR_DRIVER_BLOCKED = 1275
  ERROR_INVALID_IMPORT_OF_NON_DLL = 1276
  ERROR_ACCESS_DISABLED_WEBBLADE = 1277
  ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER = 1278
  ERROR_RECOVERY_FAILURE = 1279
  ERROR_ALREADY_FIBER = 1280
  ERROR_ALREADY_THREAD = 1281
  ERROR_STACK_BUFFER_OVERRUN = 1282
  ERROR_PARAMETER_QUOTA_EXCEEDED = 1283
  ERROR_DEBUGGER_INACTIVE = 1284
  ERROR_DELAY_LOAD_FAILED = 1285
  ERROR_VDM_DISALLOWED = 1286
  ERROR_UNIDENTIFIED_ERROR = 1287
  ERROR_INVALID_CRUNTIME_PARAMETER = 1288
  ERROR_BEYOND_VDL = 1289
  ERROR_INCOMPATIBLE_SERVICE_SID_TYPE = 1290
  ERROR_DRIVER_PROCESS_TERMINATED = 1291
  ERROR_IMPLEMENTATION_LIMIT = 1292
  ERROR_PROCESS_IS_PROTECTED = 1293
  ERROR_SERVICE_NOTIFY_CLIENT_LAGGING = 1294
  ERROR_DISK_QUOTA_EXCEEDED = 1295
  ERROR_CONTENT_BLOCKED = 1296
  ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE = 1297
  ERROR_APP_HANG = 1298
  ERROR_INVALID_LABEL = 1299
  ERROR_NOT_ALL_ASSIGNED = 1300
  ERROR_SOME_NOT_MAPPED = 1301
  ERROR_NO_QUOTAS_FOR_ACCOUNT = 1302
  ERROR_LOCAL_USER_SESSION_KEY = 1303
  ERROR_NULL_LM_PASSWORD = 1304
  ERROR_UNKNOWN_REVISION = 1305
  ERROR_REVISION_MISMATCH = 1306
  ERROR_INVALID_OWNER = 1307
  ERROR_INVALID_PRIMARY_GROUP = 1308
  ERROR_NO_IMPERSONATION_TOKEN = 1309
  ERROR_CANT_DISABLE_MANDATORY = 1310
  ERROR_NO_LOGON_SERVERS = 1311
  ERROR_NO_SUCH_LOGON_SESSION = 1312
  ERROR_NO_SUCH_PRIVILEGE = 1313
  ERROR_PRIVILEGE_NOT_HELD = 1314
  ERROR_INVALID_ACCOUNT_NAME = 1315
  ERROR_USER_EXISTS = 1316
  ERROR_NO_SUCH_USER = 1317
  ERROR_GROUP_EXISTS = 1318
  ERROR_NO_SUCH_GROUP = 1319
  ERROR_MEMBER_IN_GROUP = 1320
  ERROR_MEMBER_NOT_IN_GROUP = 1321
  ERROR_LAST_ADMIN = 1322
  ERROR_WRONG_PASSWORD = 1323
  ERROR_ILL_FORMED_PASSWORD = 1324
  ERROR_PASSWORD_RESTRICTION = 1325
  ERROR_LOGON_FAILURE = 1326
  ERROR_ACCOUNT_RESTRICTION = 1327
  ERROR_INVALID_LOGON_HOURS = 1328
  ERROR_INVALID_WORKSTATION = 1329
  ERROR_PASSWORD_EXPIRED = 1330
  ERROR_ACCOUNT_DISABLED = 1331
  ERROR_NONE_MAPPED = 1332
  ERROR_TOO_MANY_LUIDS_REQUESTED = 1333
  ERROR_LUIDS_EXHAUSTED = 1334
  ERROR_INVALID_SUB_AUTHORITY = 1335
  ERROR_INVALID_ACL = 1336
  ERROR_INVALID_SID = 1337
  ERROR_INVALID_SECURITY_DESCR = 1338
  ERROR_BAD_INHERITANCE_ACL = 1340
  ERROR_SERVER_DISABLED = 1341
  ERROR_SERVER_NOT_DISABLED = 1342
  ERROR_INVALID_ID_AUTHORITY = 1343
  ERROR_ALLOTTED_SPACE_EXCEEDED = 1344
  ERROR_INVALID_GROUP_ATTRIBUTES = 1345
  ERROR_BAD_IMPERSONATION_LEVEL = 1346
  ERROR_CANT_OPEN_ANONYMOUS = 1347
  ERROR_BAD_VALIDATION_CLASS = 1348
  ERROR_BAD_TOKEN_TYPE = 1349
  ERROR_NO_SECURITY_ON_OBJECT = 1350
  ERROR_CANT_ACCESS_DOMAIN_INFO = 1351
  ERROR_INVALID_SERVER_STATE = 1352
  ERROR_INVALID_DOMAIN_STATE = 1353
  ERROR_INVALID_DOMAIN_ROLE = 1354
  ERROR_NO_SUCH_DOMAIN = 1355
  ERROR_DOMAIN_EXISTS = 1356
  ERROR_DOMAIN_LIMIT_EXCEEDED = 1357
  ERROR_INTERNAL_DB_CORRUPTION = 1358
  ERROR_INTERNAL_ERROR = 1359
  ERROR_GENERIC_NOT_MAPPED = 1360
  ERROR_BAD_DESCRIPTOR_FORMAT = 1361
  ERROR_NOT_LOGON_PROCESS = 1362
  ERROR_LOGON_SESSION_EXISTS = 1363
  ERROR_NO_SUCH_PACKAGE = 1364
  ERROR_BAD_LOGON_SESSION_STATE = 1365
  ERROR_LOGON_SESSION_COLLISION = 1366
  ERROR_INVALID_LOGON_TYPE = 1367
  ERROR_CANNOT_IMPERSONATE = 1368
  ERROR_RXACT_INVALID_STATE = 1369
  ERROR_RXACT_COMMIT_FAILURE = 1370
  ERROR_SPECIAL_ACCOUNT = 1371
  ERROR_SPECIAL_GROUP = 1372
  ERROR_SPECIAL_USER = 1373
  ERROR_MEMBERS_PRIMARY_GROUP = 1374
  ERROR_TOKEN_ALREADY_IN_USE = 1375
  ERROR_NO_SUCH_ALIAS = 1376
  ERROR_MEMBER_NOT_IN_ALIAS = 1377
  ERROR_MEMBER_IN_ALIAS = 1378
  ERROR_ALIAS_EXISTS = 1379
  ERROR_LOGON_NOT_GRANTED = 1380
  ERROR_TOO_MANY_SECRETS = 1381
  ERROR_SECRET_TOO_LONG = 1382
  ERROR_INTERNAL_DB_ERROR = 1383
  ERROR_TOO_MANY_CONTEXT_IDS = 1384
  ERROR_LOGON_TYPE_NOT_GRANTED = 1385
  ERROR_NT_CROSS_ENCRYPTION_REQUIRED = 1386
  ERROR_NO_SUCH_MEMBER = 1387
  ERROR_INVALID_MEMBER = 1388
  ERROR_TOO_MANY_SIDS = 1389
  ERROR_LM_CROSS_ENCRYPTION_REQUIRED = 1390
  ERROR_NO_INHERITANCE = 1391
  ERROR_FILE_CORRUPT = 1392
  ERROR_DISK_CORRUPT = 1393
  ERROR_NO_USER_SESSION_KEY = 1394
  ERROR_LICENSE_QUOTA_EXCEEDED = 1395
  ERROR_WRONG_TARGET_NAME = 1396
  ERROR_MUTUAL_AUTH_FAILED = 1397
  ERROR_TIME_SKEW = 1398
  ERROR_CURRENT_DOMAIN_NOT_ALLOWED = 1399
  ERROR_INVALID_WINDOW_HANDLE = 1400
  ERROR_INVALID_MENU_HANDLE = 1401
  ERROR_INVALID_CURSOR_HANDLE = 1402
  ERROR_INVALID_ACCEL_HANDLE = 1403
  ERROR_INVALID_HOOK_HANDLE = 1404
  ERROR_INVALID_DWP_HANDLE = 1405
  ERROR_TLW_WITH_WSCHILD = 1406
  ERROR_CANNOT_FIND_WND_CLASS = 1407
  ERROR_WINDOW_OF_OTHER_THREAD = 1408
  ERROR_HOTKEY_ALREADY_REGISTERED = 1409
  ERROR_CLASS_ALREADY_EXISTS = 1410
  ERROR_CLASS_DOES_NOT_EXIST = 1411
  ERROR_CLASS_HAS_WINDOWS = 1412
  ERROR_INVALID_INDEX = 1413
  ERROR_INVALID_ICON_HANDLE = 1414
  ERROR_PRIVATE_DIALOG_INDEX = 1415
  ERROR_LISTBOX_ID_NOT_FOUND = 1416
  ERROR_NO_WILDCARD_CHARACTERS = 1417
  ERROR_CLIPBOARD_NOT_OPEN = 1418
  ERROR_HOTKEY_NOT_REGISTERED = 1419
  ERROR_WINDOW_NOT_DIALOG = 1420
  ERROR_CONTROL_ID_NOT_FOUND = 1421
  ERROR_INVALID_COMBOBOX_MESSAGE = 1422
  ERROR_WINDOW_NOT_COMBOBOX = 1423
  ERROR_INVALID_EDIT_HEIGHT = 1424
  ERROR_DC_NOT_FOUND = 1425
  ERROR_INVALID_HOOK_FILTER = 1426
  ERROR_INVALID_FILTER_PROC = 1427
  ERROR_HOOK_NEEDS_HMOD = 1428
  ERROR_GLOBAL_ONLY_HOOK = 1429
  ERROR_JOURNAL_HOOK_SET = 1430
  ERROR_HOOK_NOT_INSTALLED = 1431
  ERROR_INVALID_LB_MESSAGE = 1432
  ERROR_SETCOUNT_ON_BAD_LB = 1433
  ERROR_LB_WITHOUT_TABSTOPS = 1434
  ERROR_DESTROY_OBJECT_OF_OTHER_THREAD = 1435
  ERROR_CHILD_WINDOW_MENU = 1436
  ERROR_NO_SYSTEM_MENU = 1437
  ERROR_INVALID_MSGBOX_STYLE = 1438
  ERROR_INVALID_SPI_VALUE = 1439
  ERROR_SCREEN_ALREADY_LOCKED = 1440
  ERROR_HWNDS_HAVE_DIFF_PARENT = 1441
  ERROR_NOT_CHILD_WINDOW = 1442
  ERROR_INVALID_GW_COMMAND = 1443
  ERROR_INVALID_THREAD_ID = 1444
  ERROR_NON_MDICHILD_WINDOW = 1445
  ERROR_POPUP_ALREADY_ACTIVE = 1446
  ERROR_NO_SCROLLBARS = 1447
  ERROR_INVALID_SCROLLBAR_RANGE = 1448
  ERROR_INVALID_SHOWWIN_COMMAND = 1449
  ERROR_NO_SYSTEM_RESOURCES = 1450
  ERROR_NONPAGED_SYSTEM_RESOURCES = 1451
  ERROR_PAGED_SYSTEM_RESOURCES = 1452
  ERROR_WORKING_SET_QUOTA = 1453
  ERROR_PAGEFILE_QUOTA = 1454
  ERROR_COMMITMENT_LIMIT = 1455
  ERROR_MENU_ITEM_NOT_FOUND = 1456
  ERROR_INVALID_KEYBOARD_HANDLE = 1457
  ERROR_HOOK_TYPE_NOT_ALLOWED = 1458
  ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION = 1459
  ERROR_TIMEOUT = 1460
  ERROR_INVALID_MONITOR_HANDLE = 1461
  ERROR_INCORRECT_SIZE = 1462
  ERROR_SYMLINK_CLASS_DISABLED = 1463
  ERROR_SYMLINK_NOT_SUPPORTED = 1464
  ERROR_XML_PARSE_ERROR = 1465
  ERROR_XMLDSIG_ERROR = 1466
  ERROR_RESTART_APPLICATION = 1467
  ERROR_WRONG_COMPARTMENT = 1468
  ERROR_AUTHIP_FAILURE = 1469
  ERROR_NO_NVRAM_RESOURCES = 1470
  ERROR_NOT_GUI_PROCESS = 1471
  ERROR_EVENTLOG_FILE_CORRUPT = 1500
  ERROR_EVENTLOG_CANT_START = 1501
  ERROR_LOG_FILE_FULL = 1502
  ERROR_EVENTLOG_FILE_CHANGED = 1503
  ERROR_CONTAINER_ASSIGNED = 1504
  ERROR_JOB_NO_CONTAINER = 1505
  ERROR_INVALID_TASK_NAME = 1550
  ERROR_INVALID_TASK_INDEX = 1551
  ERROR_THREAD_ALREADY_IN_TASK = 1552
  ERROR_INSTALL_SERVICE_FAILURE = 1601
  ERROR_INSTALL_USEREXIT = 1602
  ERROR_INSTALL_FAILURE = 1603
  ERROR_INSTALL_SUSPEND = 1604
  ERROR_UNKNOWN_PRODUCT = 1605
  ERROR_UNKNOWN_FEATURE = 1606
  ERROR_UNKNOWN_COMPONENT = 1607
  ERROR_UNKNOWN_PROPERTY = 1608
  ERROR_INVALID_HANDLE_STATE = 1609
  ERROR_BAD_CONFIGURATION = 1610
  ERROR_INDEX_ABSENT = 1611
  ERROR_INSTALL_SOURCE_ABSENT = 1612
  ERROR_INSTALL_PACKAGE_VERSION = 1613
  ERROR_PRODUCT_UNINSTALLED = 1614
  ERROR_BAD_QUERY_SYNTAX = 1615
  ERROR_INVALID_FIELD = 1616
  ERROR_DEVICE_REMOVED = 1617
  ERROR_INSTALL_ALREADY_RUNNING = 1618
  ERROR_INSTALL_PACKAGE_OPEN_FAILED = 1619
  ERROR_INSTALL_PACKAGE_INVALID = 1620
  ERROR_INSTALL_UI_FAILURE = 1621
  ERROR_INSTALL_LOG_FAILURE = 1622
  ERROR_INSTALL_LANGUAGE_UNSUPPORTED = 1623
  ERROR_INSTALL_TRANSFORM_FAILURE = 1624
  ERROR_INSTALL_PACKAGE_REJECTED = 1625
  ERROR_FUNCTION_NOT_CALLED = 1626
  ERROR_FUNCTION_FAILED = 1627
  ERROR_INVALID_TABLE = 1628
  ERROR_DATATYPE_MISMATCH = 1629
  ERROR_UNSUPPORTED_TYPE = 1630
  ERROR_CREATE_FAILED = 1631
  ERROR_INSTALL_TEMP_UNWRITABLE = 1632
  ERROR_INSTALL_PLATFORM_UNSUPPORTED = 1633
  ERROR_INSTALL_NOTUSED = 1634
  ERROR_PATCH_PACKAGE_OPEN_FAILED = 1635
  ERROR_PATCH_PACKAGE_INVALID = 1636
  ERROR_PATCH_PACKAGE_UNSUPPORTED = 1637
  ERROR_PRODUCT_VERSION = 1638
  ERROR_INVALID_COMMAND_LINE = 1639
  ERROR_INSTALL_REMOTE_DISALLOWED = 1640
  ERROR_SUCCESS_REBOOT_INITIATED = 1641
  ERROR_PATCH_TARGET_NOT_FOUND = 1642
  ERROR_PATCH_PACKAGE_REJECTED = 1643
  ERROR_INSTALL_TRANSFORM_REJECTED = 1644
  ERROR_INSTALL_REMOTE_PROHIBITED = 1645
  ERROR_PATCH_REMOVAL_UNSUPPORTED = 1646
  ERROR_UNKNOWN_PATCH = 1647
  ERROR_PATCH_NO_SEQUENCE = 1648
  ERROR_PATCH_REMOVAL_DISALLOWED = 1649
  ERROR_INVALID_PATCH_XML = 1650
  ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT = 1651
  ERROR_INSTALL_SERVICE_SAFEBOOT = 1652
  ERROR_FAIL_FAST_EXCEPTION = 1653
  ERROR_INSTALL_REJECTED = 1654
  ERROR_DYNAMIC_CODE_BLOCKED = 1655
  ERROR_NOT_SAME_OBJECT = 1656
  ERROR_STRICT_CFG_VIOLATION = 1657
  ERROR_SET_CONTEXT_DENIED = 1660
  ERROR_CROSS_PARTITION_VIOLATION = 1661
  ERROR_RETURN_ADDRESS_HIJACK_ATTEMPT = 1662
end
