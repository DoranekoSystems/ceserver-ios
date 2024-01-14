#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <zlib.h>

#include <errno.h>
#include <signal.h>

#include <thread>

#include "api.h"
#include "binaryio.h"
#include "ceserver.h"
#include "lldb-auto.h"
#include "threads.h"

#define CESERVERVERSION 6 // 6 because modulelist got changed
#define MSG_MORE 0x10

char versionstring[] = "CHEATENGINE Network 2.3";

__thread int isDebuggerThread; // 0 when not, else it contains the processhandle
__thread int debugfd;

__thread char *threadname;

LLDBAutomation *lldb;

std::map<int, std::string> command_map = {
    {0, "CMD_GETVERSION"},
    {1, "CMD_CLOSECONNECTION"},
    {2, "CMD_TERMINATESERVER"},
    {3, "CMD_OPENPROCESS"},
    {4, "CMD_CREATETOOLHELP32SNAPSHOT"},
    {5, "CMD_PROCESS32FIRST"},
    {6, "CMD_PROCESS32NEXT"},
    {7, "CMD_CLOSEHANDLE"},
    {8, "CMD_VIRTUALQUERYEX"},
    {9, "CMD_READPROCESSMEMORY"},
    {10, "CMD_WRITEPROCESSMEMORY"},
    {11, "CMD_STARTDEBUG"},
    {12, "CMD_STOPDEBUG"},
    {13, "CMD_WAITFORDEBUGEVENT"},
    {14, "CMD_CONTINUEFROMDEBUGEVENT"},
    {15, "CMD_SETBREAKPOINT"},
    {16, "CMD_REMOVEBREAKPOINT"},
    {17, "CMD_SUSPENDTHREAD"},
    {18, "CMD_RESUMETHREAD"},
    {19, "CMD_GETTHREADCONTEXT"},
    {20, "CMD_SETTHREADCONTEXT"},
    {21, "CMD_GETARCHITECTURE"},
    {22, "CMD_MODULE32FIRST"},
    {23, "CMD_MODULE32NEXT"},
    {24, "CMD_GETSYMBOLLISTFROMFILE"},
    {25, "CMD_LOADEXTENSION"},
    {26, "CMD_ALLOC"},
    {27, "CMD_FREE"},
    {28, "CMD_CREATETHREAD"},
    {29, "CMD_LOADMODULE"},
    {30, "CMD_SPEEDHACK_SETSPEED"},
    {31, "CMD_VIRTUALQUERYEXFULL"},
    {32, "CMD_GETREGIONINFO"},
    {33, "CMD_GETABI"},
    {34, "CMD_SET_CONNECTION_NAME"},
    {35, "CMD_CREATETOOLHELP32SNAPSHOTEX"},
    {36, "CMD_CHANGEMEMORYPROTECTION"},
    {37, "CMD_GETOPTIONS"},
    {38, "CMD_GETOPTIONVALUE"},
    {39, "CMD_SETOPTIONVALUE"},
    {40, "CMD_PTRACE_MMAP"},
    {41, "CMD_OPENNAMEDPIPE"},
    {42, "CMD_PIPEREAD"},
    {43, "CMD_PIPEWRITE"},
    {44, "CMD_GETCESERVERPATH"},
    {45, "CMD_ISANDROID"},
    {46, "CMD_LOADMODULEEX"},
    {47, "CMD_SETCURRENTPATH"},
    {48, "CMD_GETCURRENTPATH"},
    {49, "CMD_ENUMFILES"},
    {50, "CMD_GETFILEPERMISSIONS"},
    {51, "CMD_SETFILEPERMISSIONS"},
    {52, "CMD_GETFILE"},
    {53, "CMD_PUTFILE"},
    {54, "CMD_CREATEDIR"},
    {55, "CMD_DELETEFILE"},
    {200, "CMD_AOBSCAN"},
    {255, "CMD_COMMANDLIST2"}};

std::string get_command_name(int cmd) {
  auto it = command_map.find(cmd);
  if (it != command_map.end()) {
    return it->second;
  } else {
    return "UNKNOWN_COMMAND";
  }
}

int DispatchCommand(int currentsocket, unsigned char command) {

  int r;

  BinaryReader *reader = new BinaryReader(currentsocket);
  BinaryWriter *writer = new BinaryWriter(currentsocket);
  // printf("socket:%d command:%s\n", currentsocket,
  //        get_command_name(command).c_str());

  switch (command) {
  case CMD_GETVERSION: {
    PCeVersion v;
    // debug_log("version request");
    fflush(stdout);
    int versionsize = strlen(versionstring);
#ifdef SHARED_LIBRARY
    versionsize += 3;
#endif
    v = (PCeVersion)malloc(sizeof(CeVersion) + versionsize);
    v->stringsize = versionsize;
    v->version = CESERVERVERSION;

#ifdef SHARED_LIBRARY
    memcpy((char *)v + sizeof(CeVersion), "lib",
           3); // tell ce it's the lib version
    memcpy((char *)v + sizeof(CeVersion) + 3, versionstring, versionsize);

#else
    memcpy((char *)v + sizeof(CeVersion), versionstring, versionsize);
#endif

    // version request
    sendall(currentsocket, v, sizeof(CeVersion) + versionsize, 0);

    free(v);

    break;
  }
  case CMD_SET_CONNECTION_NAME: {
    printf("CMD_SET_CONNECTION_NAME\n");
    uint32_t namelength;

    if (recvall(currentsocket, &namelength, sizeof(namelength), MSG_WAITALL) >
        0) {
      char name[namelength + 1];

      recvall(currentsocket, name, namelength, MSG_WAITALL);
      name[namelength] = 0;

      if (threadname) {
        free(threadname);
        threadname = NULL;
      }
      threadname = strdup(name);

      printf("This thread is called %s\n", name);
    }

    fflush(stdout);

    break;
  }
  case CMD_GETABI: {
#ifdef WINDOWS
    unsigned char abi = 0;
#else
    unsigned char abi = 1;
#endif
    sendall(currentsocket, &abi, sizeof(abi), 0);
    break;
  }

  case CMD_GETARCHITECTURE: {
    unsigned char arch;
    HANDLE h;
    // ce 7.4.1+ : Added the processhandle

    debug_log("CMD_GETARCHITECTURE\n");

    if (recvall(currentsocket, &h, sizeof(h), MSG_WAITALL) > 0) {
      // intel i386=0
      // intel x86_64=1
      // arm 32 = 2
      // arm 64 = 3
      debug_log("(%d)", h);
      arch = getArchitecture(h);
    }

    debug_log("=%d\n", arch);
    sendall(currentsocket, &arch, sizeof(arch), 0);
    break;
  }
  case CMD_GETREGIONINFO:
  case CMD_VIRTUALQUERYEX: {
    CeVirtualQueryExInput c;
    r = recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    if (r > 0) {
      RegionInfo rinfo;
      CeVirtualQueryExOutput o;

      if (sizeof(uintptr_t) == 4) {
        if (c.baseaddress > 0xFFFFFFFF) {
          o.result = 0;
          sendall(currentsocket, &o, sizeof(o), 0);
          break;
        }
      }
      char mapsline[200];
      if (command == CMD_VIRTUALQUERYEX)
        o.result = VirtualQueryEx(c.handle, (void *)(uintptr_t)c.baseaddress,
                                  &rinfo, NULL);
      else if (command == CMD_GETREGIONINFO)
        o.result = VirtualQueryEx(c.handle, (void *)(uintptr_t)c.baseaddress,
                                  &rinfo, mapsline);
      o.protection = rinfo.protection;
      o.baseaddress = rinfo.baseaddress;
      o.type = rinfo.type;
      o.size = rinfo.size;
      if (command == CMD_VIRTUALQUERYEX)
        sendall(currentsocket, &o, sizeof(o), 0);
      else if (command == CMD_GETREGIONINFO) {
        sendall(currentsocket, &o, sizeof(o), 0);
        {
          uint8_t size = strlen(mapsline);
          sendall(currentsocket, &size, sizeof(size), 0);
          sendall(currentsocket, mapsline, size, 0);
        }
      }
    }
    break;
  }
  case CMD_OPENPROCESS: {
    int pid = 0;

    r = recvall(currentsocket, &pid, sizeof(int), MSG_WAITALL);
    if (r > 0) {
      int processhandle;

      printf("OpenProcess(%d)\n", pid);
      processhandle = OpenProcess(pid);

      printf("processhandle=%d\n", processhandle);
      sendall(currentsocket, &processhandle, sizeof(int), 0);
    } else {
      printf("Error\n");
      fflush(stdout);
      close(currentsocket);
      return 0;
    }
    break;
  }

  case CMD_GETSYMBOLLISTFROMFILE: {
    // get the list and send it to the client
    // zip it first
    struct {
      uint32_t fileoffset;
      uint32_t symbolpathsize;
    } input;

    // if (recvall(currentsocket, &input, sizeof(input), MSG_WAITALL) > 0) {
    // if (input.fileoffset)
    // debug_log("CMD_GETSYMBOLLISTFROMFILE with fileoffset=%x\n",
    //         input.fileoffset);

    char *symbolpath = (char *)malloc(input.symbolpathsize + 1);
    symbolpath[input.symbolpathsize] = '\0';

    if (recvall(currentsocket, symbolpath, input.symbolpathsize, MSG_WAITALL) >
        0) {
      unsigned char *output = NULL;

      if (input.fileoffset)
        debug_log("symbolpath=%s\n", symbolpath);

      if (output) {
        if (input.fileoffset) {
          debug_log("output is not NULL (%p)\n", output);
          debug_log("Sending %d bytes\n", *(uint32_t *)&output[4]);
          fflush(stdout);
        }
        sendall(currentsocket, output, *(uint32_t *)&output[4],
                0); // the output buffer contains the size itself
        free(output);
      } else {
        if (input.fileoffset)
          debug_log("Sending 8 bytes (fail)\n");

        uint64_t fail = 0;
        sendall(currentsocket, &fail, sizeof(fail), 0); // just write 0
      }
    } else {
      // debug_log("Failure getting symbol path\n");
      close(currentsocket);
    }
    free(symbolpath);
    //}
    break;
  }

  case CMD_MODULE32FIRST: // slightly obsolete now
  case CMD_MODULE32NEXT: {
    HANDLE toolhelpsnapshot;
    if (recvall(currentsocket, &toolhelpsnapshot, sizeof(toolhelpsnapshot),
                MSG_WAITALL) > 0) {
      bool result;
      ModuleListEntry me;
      CeModuleEntry *r;
      int size;

      if (command == CMD_MODULE32FIRST)
        result = Module32First(toolhelpsnapshot, &me);
      else
        result = Module32Next(toolhelpsnapshot, &me);
      if (result) {
        size = sizeof(CeModuleEntry) + strlen(me.moduleName);
        r = (PCeModuleEntry)malloc(size);
        r->modulebase = me.baseAddress;
        r->modulesize = me.moduleSize;
        r->modulenamesize = strlen(me.moduleName);
        r->modulefileoffset = me.fileOffset;
        r->modulepart = me.part;

        // Sending %s size %x\n, me.moduleName, r->modulesize
        memcpy((char *)r + sizeof(CeModuleEntry), me.moduleName,
               r->modulenamesize);
      } else {
        size = sizeof(CeModuleEntry);
        r = (PCeModuleEntry)malloc(size);
        r->modulebase = 0;
        r->modulesize = 0;
        r->modulenamesize = 0;
        r->modulepart = 0;
      }

      r->result = result;
      sendall(currentsocket, r, size, 0);

      free(r);
    }
    break;
  }

  case CMD_PROCESS32FIRST: // obsolete
  case CMD_PROCESS32NEXT: {
    HANDLE toolhelpsnapshot;
    if (recvall(currentsocket, &toolhelpsnapshot, sizeof(toolhelpsnapshot),
                MSG_WAITALL) > 0) {
      ProcessListEntry pe;
      bool result;
      CeProcessEntry *r;
      int size;

      if (command == CMD_PROCESS32FIRST)
        result = Process32First(toolhelpsnapshot, &pe);
      else
        result = Process32Next(toolhelpsnapshot, &pe);

      //  debug_log("result=%d\n", result);

      if (result) {
        size = sizeof(CeProcessEntry) + strlen(pe.ProcessName);
        r = (PCeProcessEntry)malloc(size);
        r->processnamesize = strlen(pe.ProcessName);
        r->pid = pe.PID;
        memcpy((char *)r + sizeof(CeProcessEntry), pe.ProcessName,
               r->processnamesize);
      } else {
        size = sizeof(CeProcessEntry);
        r = (PCeProcessEntry)malloc(size);
        r->processnamesize = 0;
        r->pid = 0;
      }

      r->result = result;

      sendall(currentsocket, r, size, 0);

      free(r);
    }
    break;
  }
  case CMD_READPROCESSMEMORY: {
    CeReadProcessMemoryInput c;
    r = recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    if (r > 0) {
      PCeReadProcessMemoryOutput o = NULL;
      o = (PCeReadProcessMemoryOutput)malloc(sizeof(CeReadProcessMemoryOutput) +
                                             c.size);
      o->read = ReadProcessMemory((int)c.handle, (void *)(uintptr_t)c.address,
                                  &o[1], c.size);
      if (c.compress) {
// compress the output
#define COMPRESS_BLOCKSIZE (64 * 1024)
        int i;
        unsigned char *uncompressed = (unsigned char *)&o[1];
        uint32_t uncompressedSize = o->read;
        uint32_t compressedSize = 0;
        int maxBlocks = 1 + (c.size / COMPRESS_BLOCKSIZE);

        unsigned char **compressedBlocks = (unsigned char **)malloc(
            maxBlocks *
            sizeof(
                unsigned char *)); // send in blocks of 64kb and reallocate the
                                   // pointerblock if there's not enough space
        int currentBlock = 0;

        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        deflateInit(&strm, c.compress);

        compressedBlocks[currentBlock] =
            (unsigned char *)malloc(COMPRESS_BLOCKSIZE);
        strm.avail_out = COMPRESS_BLOCKSIZE;
        strm.next_out = compressedBlocks[currentBlock];

        strm.next_in = uncompressed;
        strm.avail_in = uncompressedSize;

        while (strm.avail_in) {
          r = deflate(&strm, Z_NO_FLUSH);
          if (r != Z_OK) {
            if (r == Z_STREAM_END)
              break;
            else {
              printf("Error while compressing\n");
              break;
            }
          }

          if (strm.avail_out == 0) {
            // new output block
            currentBlock++;
            if (currentBlock >= maxBlocks) {
              // list was too short, reallocate
              printf("Need to realloc the pointerlist (p1)\n");

              maxBlocks *= 2;
              compressedBlocks = (unsigned char **)realloc(
                  compressedBlocks, maxBlocks * sizeof(unsigned char *));
            }
            compressedBlocks[currentBlock] =
                (unsigned char *)malloc(COMPRESS_BLOCKSIZE);
            strm.avail_out = COMPRESS_BLOCKSIZE;
            strm.next_out = compressedBlocks[currentBlock];
          }
        }
        // finishing compressiong
        while (1) {

          r = deflate(&strm, Z_FINISH);

          if (r == Z_STREAM_END)
            break; // done

          if (r != Z_OK) {
            printf("Failure while finishing compression:%d\n", r);
            break;
          }

          if (strm.avail_out == 0) {
            // new output block
            currentBlock++;
            if (currentBlock >= maxBlocks) {
              // list was too short, reallocate
              printf("Need to realloc the pointerlist (p2)\n");
              maxBlocks *= 2;
              compressedBlocks = (unsigned char **)realloc(
                  compressedBlocks, maxBlocks * sizeof(unsigned char *));
            }
            compressedBlocks[currentBlock] =
                (unsigned char *)malloc(COMPRESS_BLOCKSIZE);
            strm.avail_out = COMPRESS_BLOCKSIZE;
            strm.next_out = compressedBlocks[currentBlock];
          }
        }
        deflateEnd(&strm);

        compressedSize = strm.total_out;
        // Sending compressed data
        sendall(currentsocket, &uncompressedSize, sizeof(uncompressedSize),
                MSG_MORE); // followed by the compressed size
        sendall(currentsocket, &compressedSize, sizeof(compressedSize),
                MSG_MORE); // the compressed data follows
        for (i = 0; i <= currentBlock; i++) {
          if (i != currentBlock)
            sendall(currentsocket, compressedBlocks[i], COMPRESS_BLOCKSIZE,
                    MSG_MORE);
          else
            sendall(currentsocket, compressedBlocks[i],
                    COMPRESS_BLOCKSIZE - strm.avail_out, 0); // last one, flush

          free(compressedBlocks[i]);
        }
        free(compressedBlocks);
      } else {
        sendall(currentsocket, o, sizeof(CeReadProcessMemoryOutput) + o->read,
                0);
      }
      if (o)
        free(o);
    }
    break;
  }
  case CMD_WRITEPROCESSMEMORY: {
    CeWriteProcessMemoryInput c;

    debug_log("CMD_WRITEPROCESSMEMORY:\n");

    r = recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    if (r > 0) {
      CeWriteProcessMemoryOutput o;
      unsigned char *buf;

      debug_log("recv returned %d bytes\n", r);
      debug_log("c.size=%d\n", c.size);

      if (c.size) {
        buf = (unsigned char *)malloc(c.size);

        r = recvall(currentsocket, buf, c.size, MSG_WAITALL);
        if (r > 0) {
          debug_log("received %d bytes for the buffer. Wanted %d\n", r, c.size);
          o.written = WriteProcessMemory(c.handle, (void *)(uintptr_t)c.address,
                                         buf, c.size);

          r = sendall(currentsocket, &o, sizeof(CeWriteProcessMemoryOutput), 0);
          debug_log("wpm: returned %d bytes to caller\n", r);

        } else
          debug_log("wpm recv error while reading the data\n");

        free(buf);
      } else {
        debug_log("wpm with a size of 0 bytes");
        o.written = 0;
        r = sendall(currentsocket, &o, sizeof(CeWriteProcessMemoryOutput), 0);
        debug_log("wpm: returned %d bytes to caller\n", r);
      }
    } else {
      debug_log("RPM: recv failed\n");
    }
    break;
  }
  case CMD_VIRTUALQUERYEXFULL: {
    CeVirtualQueryExFullInput c;

    r = recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    if (r > 0) {
      RegionInfo *rinfo = NULL;
      uint32_t count = 0;
      if (VirtualQueryExFull(c.handle, c.flags, &rinfo, &count)) {
        int i;

        sendall(currentsocket, &count, sizeof(count), 0);

        for (i = 0; i < count; i++)
          sendall(currentsocket, &rinfo[i], sizeof(RegionInfo), 0);

        if (rinfo)
          free(rinfo);
      }
    }
    break;
  }
  case CMD_GETOPTIONS: {
    int16_t value = 0;
    sendall(currentsocket, &value, sizeof(value), 0);
    break;
  }
  case CMD_CLOSEHANDLE: {
    HANDLE h;

    if (recvall(currentsocket, &h, sizeof(h), MSG_WAITALL) > 0) {
      CloseHandle(h);
      int r = 1;
      sendall(currentsocket, &r, sizeof(r), 0); // stupid naggle

    } else {
      debug_log("Error during read for CMD_CLOSEHANDLE\n");
      close(currentsocket);
      fflush(stdout);
      return 0;
    }
    break;
  }
  case CMD_CREATETOOLHELP32SNAPSHOTEX: {
    CeCreateToolhelp32Snapshot params;
    // debug_log("CMD_CREATETOOLHELP32SNAPSHOTEX\n");

    if (recvall(currentsocket, &params, sizeof(CeCreateToolhelp32Snapshot),
                MSG_WAITALL) > 0) {
      HANDLE r = CreateToolhelp32Snapshot(params.dwFlags, params.th32ProcessID);

      if ((params.dwFlags & TH32CS_SNAPTHREAD) == TH32CS_SNAPTHREAD) {
        // send the list of threadid's

        if (r) {
          PThreadList tl = (PThreadList)GetPointerFromHandle(r);
          sendall(currentsocket, &tl->threadCount, sizeof(int), MSG_MORE);
          sendall(currentsocket, &tl->threadList[0],
                  tl->threadCount * sizeof(int), 0);

          CloseHandle(r);
        } else {
          int n = 0;
          sendall(currentsocket, &n, sizeof(int), 0);
        }
      } else if ((params.dwFlags & TH32CS_SNAPMODULE) == TH32CS_SNAPMODULE) {
        ModuleListEntry me;

        char *outputstream;
        int pos = 0;

        // debug_log("CMD_CREATETOOLHELP32SNAPSHOTEX with TH32CS_SNAPMODULE\n");

        outputstream = (char *)malloc(65536);
        memset(outputstream, 0, 65536);

        if (r && (Module32First(r, &me)))
          do {
            int namelen = strlen(me.moduleName);
            PCeModuleEntry m;

            if ((pos + sizeof(CeModuleEntry) + namelen) > 65536) {
              // flush the stream
              // debug_log("CMD_CREATETOOLHELP32SNAPSHOTEX: ModuleList flush in
              // loop\n");
              sendall(currentsocket, outputstream, pos, 0);
              pos = 0;
            }

            m = (PCeModuleEntry)&outputstream[pos];
            m->modulebase = me.baseAddress;
            m->modulesize = me.moduleSize;
            // m->modulefileoffset = me.fileOffset;
            m->modulenamesize = namelen;
            m->modulepart = me.part;
            m->result = 1;
            // Sending %s size %x\n, me.moduleName, r->modulesize
            memcpy((char *)m + sizeof(CeModuleEntry), me.moduleName, namelen);

            pos += sizeof(CeModuleEntry) + namelen;

          } while (Module32Next(r, &me));

        if (pos) // flush the stream
        {
          // debug_log("CMD_CREATETOOLHELP32SNAPSHOTEX: ModuleList flush after
          // loop\n");
          sendall(currentsocket, outputstream, pos, 0);
        }

        // send the end of list module
        // debug_log("CMD_CREATETOOLHELP32SNAPSHOTEX: ModuleList end of
        // list\n");

        CeModuleEntry eol;
        eol.result = 0;
        eol.modulenamesize = 0;
        sendall(currentsocket, &eol, sizeof(eol), 0);
        free(outputstream);

        if (r)
          CloseHandle(r);

      } else {
        sendall(currentsocket, &r, sizeof(HANDLE),
                0); // the others are not yet implemented
      }
    } else {
      debug_log("Error during read for CMD_CREATETOOLHELP32SNAPSHOTEX\n");
      fflush(stdout);
      close(currentsocket);
      return 0;
    }
    break;
  }
  case CMD_CREATETOOLHELP32SNAPSHOT: {
    CeCreateToolhelp32Snapshot params;
    HANDLE result;

    // debug_log("CMD_CREATETOOLHELP32SNAPSHOT\n");

    if (recvall(currentsocket, &params, sizeof(CeCreateToolhelp32Snapshot),
                MSG_WAITALL) > 0) {
      // debug_log("Calling CreateToolhelp32Snapshot\n");
      result = CreateToolhelp32Snapshot(params.dwFlags, params.th32ProcessID);
      // debug_log("result of CreateToolhelp32Snapshot=%d\n", result);

      // fflush(stdout);

      sendall(currentsocket, &result, sizeof(HANDLE), 0);

    } else {
      printf("Error during read for CMD_CREATETOOLHELP32SNAPSHOT\n");
      fflush(stdout);
      close(currentsocket);
      return 0;
    }
    break;
  }
  case CMD_STARTDEBUG: {
    int32_t handle = reader->Read<int32_t>();
    lldb = new LLDBAutomation("127.0.0.1", 1234);
    PProcessData p = (PProcessData)GetPointerFromHandle(handle);
    lldb->attach(p->pid);
    std::thread t1(&LLDBAutomation::debugger_thread, lldb);
    t1.detach();
    std::thread t2(&LLDBAutomation::interrupt_func, lldb);
    t2.detach();
    CustomDebugEvent *event = new CustomDebugEvent();
    event->debugevent = -2;
    event->threadid = p->pid;
    lldb->debugevent.push_back(*event);
    writer->Write<int32_t>(1);
    break;
  }

  case CMD_WAITFORDEBUGEVENT: {
    int32_t handle = reader->Read<int32_t>();
    int32_t timeout = reader->Read<int32_t>();
    if (lldb->debugevent.size() > 0) {
      writer->Write<int32_t>(1);
      auto event = lldb->debugevent.back();
      lldb->debugevent.pop_back();
      int debugevent = event.debugevent;
      int threadid = event.threadid;
      if (debugevent == -2) {
        writer->Write<int32_t>(debugevent);
        writer->Write<int64_t>(threadid);
        writer->Write<int8_t>(4);
        writer->Write<int8_t>(4);
        writer->Write<int8_t>(4);
        // 5byte:0
        writer->Write<int32_t>(0);
        writer->Write<int8_t>(0);
      } else if (debugevent == 5) {
        lldb->register_info = event.register_;
        writer->Write<int32_t>(debugevent);
        writer->Write<int64_t>(threadid);
        writer->Write<uint64_t>(event.address);
      }
    } else {
      usleep(100000); // 0.1
      writer->Write<int32_t>(0);
    }
    break;
  }
  case CMD_CONTINUEFROMDEBUGEVENT: {
    int handle = reader->Read<int32_t>();
    int tid = reader->Read<int32_t>();
    int ignore = reader->Read<int32_t>();
    lldb->continue_queue.put(std::make_pair(ignore, tid));
    writer->Write<int32_t>(1);
    break;
  }
  case CMD_SETBREAKPOINT: {
    int handle = reader->Read<int32_t>();
    int tid = reader->Read<int32_t>();
    int debugreg = reader->Read<int32_t>();
    uint64_t address = reader->Read<uint64_t>();
    int bptype = reader->Read<int32_t>();
    int bpsize = reader->Read<int32_t>();
    auto wp = lldb->wpinfo[debugreg];
    // auto
    if (tid != -1) {
      if (lldb->is_stopped) {
        lldb->set_watchpoint(address, wp.bpsize, wp.type);
      }
      writer->Write<int32_t>(1);
    }
    // manual
    else {
      bool enabled = false;
      if (wp.switch_ == false && wp.enabled == false) {
        char _type;
        switch (bptype) {
        case 0: {
          _type = 'x';
          bpsize = 4;
          break;
        }
        case 1: {
          _type = 'w';
          break;
        }
        case 2: {
          _type = 'r';
          break;
        }
        case 3: {
          _type = 'a';
          break;
        }
        }
        if (lldb->is_stopped) {
          bool ret = lldb->set_watchpoint(address, bpsize, _type);
          enabled = true;
        } else {
          printf("CMD_SETBREAKPOINT\n");
          enabled = false;
        }

        WPInfo bp;
        bp.address = address;
        bp.bpsize = bpsize;
        bp.type = _type;
        bp.switch_ = true;
        bp.enabled = enabled;
        lldb->wpinfo[debugreg] = bp;
        writer->Write<int32_t>(1);
      } else {
        writer->Write<int32_t>(0);
      }
    }
    break;
  }
  case CMD_REMOVEBREAKPOINT: {
    int handle = reader->Read<int32_t>();
    int tid = reader->Read<int32_t>();
    int debugreg = reader->Read<int32_t>();
    int wasWatchpoint = reader->Read<int32_t>();
    auto wp = lldb->wpinfo[debugreg];
    if (tid != -1) {
      if (lldb->is_stopped) {
        lldb->remove_watchpoint(wp.address, wp.bpsize, wp.type);
      }
      writer->Write<int32_t>(1);
    } else {
      if (wp.switch_ == true && wp.enabled == true) {
        if (lldb->is_stopped) {
          bool ret = lldb->remove_watchpoint(wp.address, wp.bpsize, wp.type);
          if (ret) {
            lldb->wpinfo[debugreg].enabled = false;
          }
        } else {
          printf("CMD_REMOVEBREAKPOINT\n");
        }
        lldb->wpinfo[debugreg].switch_ = false;
        writer->Write<int32_t>(1);
      } else {
        writer->Write<int32_t>(0);
      }
    }
    break;
  }
  case CMD_GETTHREADCONTEXT: {
    int handle = reader->Read<int32_t>();
    int tid = reader->Read<int32_t>();
    writer->Write<int32_t>(1);
    writer->Write<int32_t>(808);
    writer->Write<int32_t>(808);
    writer->Write<int32_t>(3);
    if (lldb->register_info.size() > 0) {
      for (auto value : lldb->register_info) {
        writer->Write<uint64_t>(value);
      }
    } else {
      char buf[8 * 34];
      memset(buf, 0, 8 * 34);
      sendall(currentsocket, buf, 8 * 34, 0);
    }
    char buf[16 * 33];
    memset(buf, 0, 16 * 33);
    sendall(currentsocket, buf, 16 * 33, 0);
    break;
  }
  case CMD_SETTHREADCONTEXT: {
    int handle = reader->Read<int32_t>();
    int tid = reader->Read<int32_t>();
    int structsize = reader->Read<int32_t>();
    char buf[structsize];
    recvall(currentsocket, buf, structsize, 0);
    writer->Write<int32_t>(1);
    break;
  }
  case CMD_ISANDROID: {
    writer->Write<int8_t>(1);
  }
  }
  return 1;
}

int newconnection(int currentsocket) {
  int r;
  unsigned char command;
  while (true) {
    r = recvall(currentsocket, &command, 1, MSG_WAITALL);
    if (r == 1) {
      DispatchCommand(currentsocket, command);
    } else if (r == 0) {
      printf("Peer has disconnected\n");
      fflush(stdout);
      close(currentsocket);
      return 0;
    } else if (r == -1) {
      printf("read error on socket\n");
      fflush(stdout);
      close(currentsocket);
      return 0;
    }
  }

  return 0;
}

int main() {
  int sock0;
  struct sockaddr_in addr;
  struct sockaddr_in client;
  socklen_t len;
  int sock;

  initAPI();
  printf("CEServer. Waiting for client connection\n");
  sock0 = socket(AF_INET, SOCK_STREAM, 0);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(52736);
  addr.sin_addr.s_addr = INADDR_ANY;

  int yes = 1;
  setsockopt(sock0, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
  bind(sock0, (struct sockaddr *)&addr, sizeof(addr));

  int l = listen(sock0, 32);
  if (l == 0)
    printf("Listening success\n");
  else
    printf("listen=%d (error)\n", l);
  len = sizeof(client);
  while (true) {
    sock = accept(sock0, (struct sockaddr *)NULL, NULL);
    printf("accept=%d\n", sock);

    fflush(stdout);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&yes, sizeof(yes));
    std::thread th1(newconnection, sock);
    th1.detach();
  }
}