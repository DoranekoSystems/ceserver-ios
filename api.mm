#include "api.h"
#include "ceserver.h"
#include "symbols.h"

sem_t sem_DebugThreadEvent;
pthread_mutex_t memorymutex;
pthread_mutex_t debugsocketmutex;

PROC_REGIONFILENAME proc_regionfilename = NULL;

extern "C" kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t,
                                                mach_vm_size_t,
                                                mach_vm_address_t,
                                                mach_vm_size_t *);

int debug_log(const char *format, ...) {
  va_list list;
  va_start(list, format);
  int ret = vprintf(format, list);
  va_end(list);
  fflush(stdout);
  return ret;
}

int getArchitecture(HANDLE hProcess) {
  if (GetHandleType(hProcess) == htProcesHandle) {
    PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
    if (true) //(p->is64bit)
#if defined(__arm__) || defined(__aarch64__)
      return 3;
    else
      return 2;
#else
      return 1;
    else
      return 0;
#endif
  }

  return -1;
}

HANDLE OpenProcess(DWORD pid) {
  // check if this process has already been opened
  int handle = SearchHandleList(
      htProcesHandle, (HANDLESEARCHCALLBACK)SearchHandleListProcessCallback,
      &pid);
  if (handle) {
    // debug_log("Already opened. Returning same handle\n");
    PProcessData p = (PProcessData)GetPointerFromHandle(handle);
    p->ReferenceCount++;
    return handle;
  }

  mach_port_t task;
  kern_return_t err = task_for_pid(mach_task_self(), pid, &task);
  if (err != KERN_SUCCESS) {
    debug_log("Failed to get task for pid %d\n", pid);
    return 0;
  }

  // create a process info structure and return a handle to it
  PProcessData p = (PProcessData)malloc(sizeof(ProcessData));

  memset(p, 0, sizeof(ProcessData));

  p->ReferenceCount = 1;
  p->pid = pid;
  p->path = strdup("");
  p->task = task;

  HANDLE result = CreateHandleFromPointer(p, htProcesHandle);
  return result;
}

int ReadProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer,
                      int size) {
  if (GetHandleType(hProcess) == htProcesHandle) {
    PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
    mach_vm_size_t size_out;
    kern_return_t kr =
        mach_vm_read_overwrite(p->task, (mach_vm_address_t)lpAddress, size,
                               (mach_vm_address_t)buffer, &size_out);
    if (kr != 0) {
      return 0;
    }
    return size_out;
  }
  return 0;
}

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
  if (dwFlags & TH32CS_SNAPPROCESS) {
    // create a processlist which process32first/process32next will make use
    // of. Not often called so you may make it as slow as you wish
    int max = 2048;
    PProcessList pl = (PProcessList)malloc(sizeof(ProcessList));

    // printf("Creating processlist\n");

    pl->ReferenceCount = 1;
    pl->processCount = 0;
    pl->processList = (PProcessListEntry)malloc(sizeof(ProcessListEntry) * max);

    size_t procCount;

    int err;
    struct kinfo_proc *result;
    bool done;
    static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t length;

    procCount = 0;

    result = NULL;
    done = false;
    do {

      length = 0;
      err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, NULL,
                   &length, NULL, 0);
      if (err == -1) {
        err = errno;
      }

      if (err == 0) {
        result = (kinfo_proc *)malloc(length);
        if (result == NULL) {
          err = ENOMEM;
        }
      }

      if (err == 0) {
        err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, result,
                     &length, NULL, 0);
        if (err == -1) {
          err = errno;
        }
        if (err == 0) {
          done = true;
        } else if (err == ENOMEM) {
          free(result);
          result = NULL;
          err = 0;
        }
      }
    } while (err == 0 && !done);

    if (err != 0 && result != NULL) {
      free(result);
      result = NULL;
    }
    if (result != NULL) {
      procCount = length / sizeof(struct kinfo_proc);
    }

    for (int i = 0; i < procCount; i++) {

      // add this process to the list
      pl->processList[pl->processCount].PID = result[i].kp_proc.p_pid;
      pl->processList[pl->processCount].ProcessName =
          strdup(result[i].kp_proc.p_comm);

      pl->processCount++;

      if (pl->processCount >= max) {
        max = max * 2;
        pl->processList = (PProcessListEntry)realloc(
            pl->processList, max * sizeof(ProcessListEntry));
      }
    }
    return CreateHandleFromPointer(pl, htTHSProcess);
  } else if (((dwFlags & TH32CS_SNAPMODULE) ||
              (dwFlags & TH32CS_SNAPFIRSTMODULE))) {
    // Reference:https://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x

    // make a list of all the modules loaded by processid th32ProcessID
    // the module list
    int max = 64;

    PModuleList ml = (PModuleList)malloc(sizeof(ModuleList));

    if (dwFlags & TH32CS_SNAPFIRSTMODULE)
      debug_log("Creating 1-entry module list for process %d\n", th32ProcessID);

    ml->ReferenceCount = 1;
    ml->moduleCount = 0;
    ml->moduleList = (PModuleListEntry)malloc(sizeof(ModuleListEntry) * max);

    PModuleListEntry mle = NULL;
    int pHandle = OpenProcess(th32ProcessID);
    PProcessData p = (PProcessData)GetPointerFromHandle(pHandle);

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(p->task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) ==
        KERN_SUCCESS) {
      mach_msg_type_number_t size = sizeof(dyld_all_image_infos);

      uint8_t *data = (uint8_t *)malloc(size);
      ReadProcessMemory(pHandle, (void *)dyld_info.all_image_info_addr, data,
                        size);
      struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)data;

      mach_msg_type_number_t size2 =
          sizeof(dyld_image_info) * infos->infoArrayCount;
      uint8_t *info_addr = (uint8_t *)malloc(size2);
      ReadProcessMemory(pHandle, (void *)infos->infoArray, info_addr, size2);
      struct dyld_image_info *info = (struct dyld_image_info *)info_addr;
      for (int i = 0; i < infos->infoArrayCount; i++) {
        mach_msg_type_number_t size3 = PATH_MAX;
        uint8_t *fpath_addr = (uint8_t *)malloc(size3);
        ReadProcessMemory(pHandle, (void *)info[i].imageFilePath, fpath_addr,
                          size3);
        if (fpath_addr) {
          mle = &ml->moduleList[ml->moduleCount];
          if (strlen((const char *)fpath_addr) == 0) {
            char buffer[PATH_MAX];
            int ret =
                proc_regionfilename(p->pid, (uint64_t)info[i].imageLoadAddress,
                                    buffer, sizeof(buffer));
            if (ret > 0) {
              mle->moduleName = strdup(buffer);
            } else {
              mle->moduleName = strdup("None");
            }
          } else {
            mle->moduleName = strdup((const char *)fpath_addr);
          }
          mle->baseAddress = (unsigned long long)info[i].imageLoadAddress;
          mle->fileOffset = 0;
          mle->moduleSize = GetModuleSize(mle->moduleName, 0, 0);
          mle->part = 0;
          mle->is64bit = 1;
          ml->moduleCount++;

          if (ml->moduleCount >= max) {
            // printf("reallocate modulelist\n");
            max = max * 2;
            ml->moduleList = (PModuleListEntry)realloc(
                ml->moduleList, max * sizeof(ModuleListEntry));
          }

          if (dwFlags & TH32CS_SNAPFIRSTMODULE)
            break;
        }
      }
    }

    CloseHandle(pHandle);
    return CreateHandleFromPointer(ml, htTHSModule);
  }
  return 0;
}

bool Process32Next(HANDLE hSnapshot, PProcessListEntry processentry) {
  // get the current iterator of the list and increase it. If the max has been
  // reached, return false
  // debug_log("Process32Next\n");

  if (GetHandleType(hSnapshot) == htTHSProcess) {
    PProcessList pl = (PProcessList)GetPointerFromHandle(hSnapshot);

    if (pl->processListIterator < pl->processCount) {
      processentry->PID = pl->processList[pl->processListIterator].PID;
      processentry->ProcessName = pl->processList[pl->processListIterator]
                                      .ProcessName; // no need to copy
      pl->processListIterator++;

      return TRUE;
    } else
      return FALSE;
  } else
    return FALSE;
}

bool Process32First(HANDLE hSnapshot, PProcessListEntry processentry) {
  // Get a processentry from the processlist snapshot. fill the given
  // processentry with the data.

  // debug_log("Process32First\n");
  if (GetHandleType(hSnapshot) == htTHSProcess) {
    PProcessList pl = (PProcessList)GetPointerFromHandle(hSnapshot);
    pl->processListIterator = 0;
    return Process32Next(hSnapshot, processentry);
  } else
    return FALSE;
}

bool Module32First(HANDLE hSnapshot, PModuleListEntry moduleentry) {
  // printf("Module32First\n");
  if (GetHandleType(hSnapshot) == htTHSModule) {
    PModuleList ml = (PModuleList)GetPointerFromHandle(hSnapshot);
    ml->moduleListIterator = 0;
    return Module32Next(hSnapshot, moduleentry);
  } else {
    debug_log("Module32First error. Handle is not a THSModule handle\n");
    return FALSE;
  }
}

bool Module32Next(HANDLE hSnapshot, PModuleListEntry moduleentry) {
  // obsolete with the new createtoolhelpsnapshotex

  // get the current iterator of the list and increase it. If the max has been
  // reached, return false
  // debug_log("Module32First/Next(%d)\n", hSnapshot);

  if (GetHandleType(hSnapshot) == htTHSModule) {
    PModuleList ml = (PModuleList)GetPointerFromHandle(hSnapshot);

    if (ml->moduleListIterator < ml->moduleCount) {
      moduleentry->baseAddress =
          ml->moduleList[ml->moduleListIterator].baseAddress;
      moduleentry->moduleName =
          ml->moduleList[ml->moduleListIterator].moduleName;
      moduleentry->moduleSize =
          ml->moduleList[ml->moduleListIterator].moduleSize;
      moduleentry->part = ml->moduleList[ml->moduleListIterator].part;
      moduleentry->fileOffset =
          ml->moduleList[ml->moduleListIterator].fileOffset;
      moduleentry->is64bit = ml->moduleList[ml->moduleListIterator].is64bit;

      ml->moduleListIterator++;

      return TRUE;
    } else {
      // debug_log("Module32First/Next: Returning false because
      // ml->moduleListIterator=%d and ml->moduleCount=%d\n",
      // ml->moduleListIterator, ml->moduleCount);
      return FALSE;
    }
  } else {
    debug_log(
        "Module32First/Next failed: Handle is not a htHTSModule handle: %d\n",
        GetHandleType(hSnapshot));
    return FALSE;
  }
}

void CloseHandle(HANDLE h) {
  int i;
  handleType ht = GetHandleType(h);

  // debug_log("CloseHandle(%d)\n", h);
  if (ht == htTHSModule) {
    ModuleList *ml = (PModuleList)GetPointerFromHandle(h);
    ml->ReferenceCount--;
    if (ml->ReferenceCount <= 0) {
      // free all the processnames in the list
      for (i = 0; i < ml->moduleCount; i++)
        free(ml->moduleList[i].moduleName);

      free(ml->moduleList); // free the list
      free(ml);             // free the descriptor

      RemoveHandle(h);
    }

  } else if (ht == htTHSProcess) {
    ProcessList *pl = (PProcessList)GetPointerFromHandle(h);

    pl->ReferenceCount--;

    if (pl->ReferenceCount <= 0) {
      // free all the processnames in the list
      for (i = 0; i < pl->processCount; i++)
        free(pl->processList[i].ProcessName);

      free(pl->processList); // free the list
      free(pl);              // free the descriptor

      RemoveHandle(h);
    }
  } else if (ht == htTHSThread) {
    ThreadList *tl = (PThreadList)GetPointerFromHandle(h);

    tl->ReferenceCount--;
    if (tl->ReferenceCount <= 0) {
      free(tl->threadList);
      RemoveHandle(h);
    }
  } else if (ht == htProcesHandle) {
    PProcessData pd = (PProcessData)GetPointerFromHandle(h);

    pd->ReferenceCount--;
    if (pd->ReferenceCount <= 0) {
      free(pd->maps);
      free(pd->path);
      close(pd->mem);
      free(pd);

      RemoveHandle(h);
    }
  } else if (ht == htNativeThreadHandle) {
    uint64_t *th = (uint64_t *)GetPointerFromHandle(h);
    debug_log("Closing thread handle\n");

    free(th);
    RemoveHandle(h);
  } else if (ht == htPipeHandle) {
    debug_log("Closing pipe handle\n");

    PPipeData pd = (PPipeData)GetPointerFromHandle(h);
    close(pd->socket);
    free(pd->pipename);
    free(pd);
    RemoveHandle(h);
  } else
    RemoveHandle(h); // no idea what it is...
}

DWORD ProtectionInfoToType(int protectioninfo) {
  // if (strchr(protectionstring, 's'))
  // return MEM_MAPPED;
  // else
  return MEM_PRIVATE;
}

uint32_t ProtectionInfoToProtection(int protectioninfo) {
  int w, x;

  if (protectioninfo & VM_PROT_EXECUTE)
    x = 1;
  else
    x = 0;

  if (protectioninfo & VM_PROT_WRITE)
    w = 1;
  else
    w = 0;

  if (x) {
    // executable
    if (w)
      return PAGE_EXECUTE_READWRITE;
    else
      return PAGE_EXECUTE_READ;
  } else {
    // not executable
    if (w)
      return PAGE_READWRITE;
    else
      return PAGE_READONLY;
  }
}

void AddToRegionList(uint64_t base, uint64_t size, uint32_t type,
                     uint32_t protection, RegionInfo **list, int *pos, int *max)
// helper function for VirtualQueryExFull to add new entries to the list
{
  // printf("Calling AddToRegionList\n");

  debug_log("++>%llx->%llx : (%llx)  - %d\n", (unsigned long long)base,
            (unsigned long long)base + size, (unsigned long long)size, type);

  (*list)[*pos].baseaddress = base;
  (*list)[*pos].size = size;
  (*list)[*pos].type = type;
  (*list)[*pos].protection = protection;

  (*pos)++;

  if (*pos >= *max) {
    debug_log("resize list\n");
    *max = (*max) * 2;
    *list = (RegionInfo *)realloc(*list, sizeof(RegionInfo) * (*max));
  }

  // printf("Returning from AddToRegionList\n");
}

int VirtualQueryExFull(HANDLE hProcess, uint32_t flags, RegionInfo **rinfo,
                       uint32_t *count)
/*
 * creates a full list of the maps file (less seeking)
 */
{
  int pagedonly = flags & VQE_PAGEDONLY;
  int dirtyonly = flags & VQE_DIRTYONLY;
  int noshared = flags & VQE_NOSHARED;

  debug_log("VirtualQueryExFull:\n");

  if (GetHandleType(hProcess) == htProcesHandle) {
    PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);

    unsigned long long start = 0, stop = 0;
    char protectionstring[25];
    char x[200];
    int pos = 0, max = pagedonly ? 64 : 128;
    RegionInfo *r;

    debug_log("going to allocate r\n");
    r = (RegionInfo *)malloc(sizeof(RegionInfo) * max);

    debug_log("Allocated r at %p\n", r);

    int isdirty = 0;
    int end = 0;

    task_t task;
    kern_return_t err;

    vm_address_t address = 0;
    vm_size_t size = 0;
    natural_t depth = 0;
    debug_log("Memory map for pid %d:\n", p->pid);
    while (true) {
      vm_region_submap_info_data_64_t info;

      mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
      if (vm_region_recurse_64(p->task, &address, &size, &depth,
                               (vm_region_info_t)&info,
                               &info_count) != KERN_SUCCESS) {
        break;
      }

      if (info.is_submap) {
        depth++;
      } else {
        DWORD
        type = ProtectionInfoToType(info.protection);
        DWORD protection = ProtectionInfoToProtection(info.protection);
        AddToRegionList(address, size, type, protection, &r, &pos, &max);
        address += size;
      }
    }

    *count = pos;
    *rinfo = r;
    return 1;
  }
  return 0;
}

int VirtualQueryEx(HANDLE hProcess, void *lpAddress, PRegionInfo rinfo,
                   char *mapsline) {
  /*
   * Alternate method: read pagemaps and look up the pfn in /proc/kpageflags
   * (needs to 2 files open and random seeks through both files, so not sure
   * if slow or painfully slow...)
   */

  // VirtualQueryEx stub port. Not a real port, and returns true if successful
  // and false on error
  int found = 0;

  if (GetHandleType(hProcess) == htProcesHandle) {
    PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
    rinfo->protection = 0;
    // debug_log("%llx - %llx : %s\n", start,stop, protectionstring);
    vm_size_t size;
    natural_t depth = 0;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    vm_region_submap_info_data_64_t info;
    uint64_t start = (uint64_t)lpAddress;
    char buf[PATH_MAX];
    memset(buf, 0, PATH_MAX);
    while (true) {
      if (vm_region_recurse_64(p->task, (vm_address_t *)&lpAddress, &size,
                               &depth, (vm_region_recurse_info_t)&info,
                               &info_count) != KERN_SUCCESS) {
        return 0;
      }
      if (info.is_submap) {
        depth++;
      } else {
        if ((uint64_t)lpAddress > start) {
          rinfo->protection = PAGE_NOACCESS;
          rinfo->type = 0;
          rinfo->baseaddress = start;
          rinfo->size = (uint64_t)lpAddress - start;
          mapsline[0] = '\x00';
        } else {
          rinfo->protection = ProtectionInfoToProtection(info.protection);
          rinfo->type = ProtectionInfoToType(info.protection);
          rinfo->baseaddress = (uint64_t)lpAddress;
          rinfo->size = size;
          if (mapsline) {
            int ret = proc_regionfilename(p->pid, start, buf, sizeof(buf));
            if (ret > 0) {
              strcpy(mapsline, buf);
            } else {
              mapsline[0] = '\x00';
            }
          }
        }
        break;
      }
    }
    return 1;
  }
  return 0;
}

int SearchHandleListProcessCallback(PProcessData data, int *pid)
/*
 * Callback. Called during the call to SearchHandleList
 * Searchdata is a pointer to the processid to be looked for
 */
{
  return (data->pid == *pid);
}

uint64_t getTickCount() {
  struct timespec ts;
  uint64_t r = 0;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  r = ts.tv_nsec / 1000000;
  r += ts.tv_sec * 1000;
  return r;
}

void initAPI() {
  pthread_mutex_init(&memorymutex, NULL);
  pthread_mutex_init(&debugsocketmutex, NULL);
  void *libsystem_kernel =
      dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW);
  if (libsystem_kernel) {
    proc_regionfilename =
        (PROC_REGIONFILENAME)dlsym(libsystem_kernel, "proc_regionfilename");
  }

  debug_log("proc_regionfilename=%llx\n", proc_regionfilename);
}