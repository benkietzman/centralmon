// vim600: fdm=marker
/* -*- c++ -*- */
///////////////////////////////////////////
// Central Monitor:  centralmon
// -------------------------------------
// file       : centralmon.cpp
// author     : Ben Kietzman
// begin      : 2008-08-08
// copyright  : kietzman.org
// email      : ben@kietzman.org
///////////////////////////////////////////

/**************************************************************************
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
**************************************************************************/

/*! \file centralmon.cpp
* \brief Central Monitor Client Daemon
*
* Analyzes and acts upon system information.
*/
// {{{ includes
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <sstream>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#ifdef SOLARIS
#include <kstat.h>
#include <procfs.h>
#endif
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef SOLARIS
#include <sys/swap.h>
#endif
#ifdef LINUX
#include <sys/sysinfo.h>
#endif
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
using namespace std;
#include <File>
#include <SignalHandling>
#include <StringManip>
#include <Utility>
using namespace common;
// }}}
// {{{ defines
#ifdef VERSION
#undef VERSION
#endif
/*! \def VERSION
* \brief Contains the application version number.
*/
#define VERSION "2.0.1"
/*! \def mUSAGE(A)
* \brief Prints the usage statement.
*/
#define mUSAGE(A) cout << endl << "Usage:  "<< A << " [options]"  << endl << endl << " -c SERVER, --central=SERVER" << endl << "     Provides the DNS name for the central host server." << endl << endl << " -d, --daemon" << endl << "     Turns the process into a daemon." << endl << endl << " -h, --help" << endl << "     Displays this usage screen." << endl << endl << " -s SERVER, --server=SERVER" << endl << "     Provides the DNS name for the local server." << endl << endl << " -v, --version" << endl << "     Displays the current version of this software." << endl << endl
/*! \def mVER_USAGE(A,B)
* \brief Prints the version number.
*/
#define mVER_USAGE(A,B) cout << endl << A << " Version: " << B << endl << endl
/*! \def LOG
* \brief Supplies the log path.
*/
#define LOG "/var/log/centralmon.log"
/*! \def PORT
* \brief Supplies the status communication port.
*/
#define PORT "4636"
#ifdef SOLARIS
/*! \def MAX_SWAP_ENTRIES
* \brief Supplies the maximum swap locations.
*/
#define MAX_SWAP_ENTRIES 100
#endif
#define PARENT_READ  readpipe[0]
#define CHILD_WRITE  readpipe[1]
#define CHILD_READ   writepipe[0]
#define PARENT_WRITE writepipe[1]
// }}}
// {{{ structs
struct overall
{
  bool bPage;
  bool bPrevPage;
  int nProcessors;
  unsigned int unCpuSpeed;
  unsigned int unCpuUsage;
  unsigned int unMaxCpuUsage;
  unsigned int unMaxDiskUsage;
  unsigned int unMaxMainUsage;
  unsigned int unMaxSwapUsage;
  unsigned short usProcesses;
  unsigned short usMaxProcesses;
  long lUpTime;
  unsigned long ulMainTotal;
  unsigned long ulMainUsed;
  unsigned long ulSwapTotal;
  unsigned long ulSwapUsed;
  string strCpuProcessUsage;
  string strOperatingSystem;
  string strSystemRelease;
  stringstream ssAlarms;
  stringstream ssPrevAlarms;
};
struct process
{
  bool bChecking;
  bool bPage;
  bool bPrevPage;
  int nProcesses;
  int nMinProcesses;
  int nMaxProcesses;
  size_t ulImage;
  size_t ulMinImage;
  size_t ulMaxImage;
  size_t ulRealMinImage;
  size_t ulRealMaxImage;
  size_t ulResident;
  size_t ulMinResident;
  size_t ulMaxResident;
  size_t ulRealMinResident;
  size_t ulRealMaxResident;
  time_t CStartTime;
  map<string, unsigned int> owner;
  string strApplicationServerID;
  string strDaemon;
  stringstream ssAlarms;
  stringstream ssPrevAlarms;
};
#ifdef SOLARIS
struct swapdata
{
  int tblcount;
  struct swapent swapdat[MAX_SWAP_ENTRIES];
};
#endif
// }}}
// {{{ global variables
extern char **environ;
static bool gbDaemon = false; //!< Global daemon variable.
static string gstrTimezonePrefix = "c"; //!< Contains the local timezone.
static Utility *gpUtility = NULL; //!< Contains the Utility class.
// }}}
// {{{ prototypes
/*! \fn string getErrorMessage(const int nError)
* \brief Retrieves the exec error message.
* \param nError Contains the error number.
* \return Returns the error message.
*/
string getErrorMessage(const int nError);
/*! \fn void log(const string strMessage)
* \brief Writes a message to the application log.
* \param strMessage Contains the message.
*/
void log(const string strMessage);
/*! \fn void sighandle(const int nSignal)
* \brief Establishes signal handling for the application.
* \param nSignal Contains the caught signal.
*/
void sighandle(const int nSignal);
// }}}
// {{{ main()
/*! \fn int main(int argc, char *argv[])
* \brief This is the main function.
* \return Exits with a return code for the operating system.
*/
int main(int argc, char *argv[])
{
  string strCentral, strError, strServer;
  File file;
  StringManip manip;

  gpUtility = new Utility(strError);
  // {{{ set signal handling
  sethandles(sighandle);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGWINCH, SIG_IGN);
  // }}}
  // {{{ command line arguments
  for (int i = 1; i < argc; i++)
  {
    string strArg = argv[i];
    if (strArg == "-c" || (strArg.size() > 10 && strArg.substr(0, 10) == "--central="))
    {
      if (strArg == "-c" && i + 1 < argc && argv[i+1][0] != '-')
      {
        strCentral = argv[++i];
      }
      else
      {
        strCentral = strArg.substr(10, strArg.size() - 10);
      }
      manip.purgeChar(strCentral, strCentral, "'");
      manip.purgeChar(strCentral, strCentral, "\"");
    }
    else if (strArg == "-d" || strArg == "--daemon")
    {
      gbDaemon = true;
    }
    else if (strArg == "-h" || strArg == "--help")
    {
      mUSAGE(argv[0]);
      return 0;
    }
    else if (strArg == "-s" || (strArg.size() > 9 && strArg.substr(0, 9) == "--server="))
    {
      if (strArg == "-s" && i + 1 < argc && argv[i+1][0] != '-')
      {
        strServer = argv[++i];
      }
      else
      {
        strServer = strArg.substr(9, strArg.size() - 9);
      }
      manip.purgeChar(strServer, strServer, "'");
      manip.purgeChar(strServer, strServer, "\"");
    }
    else if (strArg == "-v" || strArg == "--version")
    {
      mVER_USAGE(argv[0], VERSION);
      return 0;
    }
    else
    {
      cout << endl << "Illegal option, '" << strArg << "'." << endl;
      mUSAGE(argv[0]);
      return 0;
    }
  }
  // }}}
  // {{{ normal run
  if (!strCentral.empty() && !strServer.empty())
  {
    bool bReady = true;
    ifstream inFile;
    SSL_CTX *ctx = NULL;
    if (gbDaemon)
    {
      gpUtility->daemonize();
    }
    // {{{ determine timezone prefix
    inFile.open("/etc/TIMEZONE");
    if (inFile.good())
    {
      bool bDone = false;
      string strLine;
      while (!bDone && gpUtility->getLine(inFile, strLine))
      {
        manip.trim(strLine, strLine);
        if (strLine.size() > 3 && strLine.substr(0, 3) == "TZ=")
        {
          string strTimezone = strLine.substr(3, strLine.size() - 3);
          bDone = true;
          if (strTimezone == "US/Eastern")
          {
            gstrTimezonePrefix = "e";
          }
          else if (strTimezone == "US/Central")
          {
            gstrTimezonePrefix = "c";
          }
          else if (strTimezone == "US/Mountain")
          {
            gstrTimezonePrefix = "m";
          }
          else if (strTimezone == "US/Pacific")
          {
            gstrTimezonePrefix = "p";
          }
        }
      }
    }
    inFile.close();
    // }}}
    if ((ctx = gpUtility->sslInitClient(strError)) == NULL)
    {
      bReady = false;
      cerr << "Utility::sslInitClient() error:  " << strError << endl;
    }
    while (bReady)
    {
      bool bConnected = false;
      struct addrinfo hints;
      struct addrinfo *result;
      int fdSocket, nReturn;
      SSL *ssl = NULL;
      memset(&hints, 0, sizeof(struct addrinfo));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = 0;
      hints.ai_protocol = 0;
      if ((nReturn = getaddrinfo(strCentral.c_str(), PORT, &hints, &result)) == 0)
      {
        struct addrinfo *rp;
        for (rp = result; !bConnected && rp != NULL; rp = rp->ai_next)
        {
          if ((fdSocket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) >= 0)
          {
            if (connect(fdSocket, rp->ai_addr, rp->ai_addrlen) == 0)
            {
              if ((ssl = gpUtility->sslConnect(ctx, fdSocket, strError)) != NULL)
              {
                bConnected = true;
              }
              else
              {
                close(fdSocket);
              }
            }
            else
            {
              close(fdSocket);
            }
          }
        }
        freeaddrinfo(result);
      }
      if (bConnected)
      {
        bool bExit = false;
        size_t unPosition;
        string strBuffer[2];
        strBuffer[1] = (string)"server " + strServer + "\n";
        while (!bExit)
        {
          pollfd fds[1];
          fds[0].fd = fdSocket;
          fds[0].events = POLLIN;
          if (!strBuffer[1].empty())
          {
            fds[0].events |= POLLOUT;
          }
          if ((nReturn = poll(fds, 1, 250)) > 0)
          {
            if (fds[0].revents & POLLIN)
            {
              if (gpUtility->sslRead(ssl, strBuffer[0], nReturn))
              {
                while ((unPosition = strBuffer[0].find("\n")) != string::npos)
                {
                  string strAction;
                  stringstream ssLine;
                  ssLine.str(strBuffer[0].substr(0, unPosition));
                  strBuffer[0].erase(0, (unPosition + 1));
                  ssLine >> strAction;
                  if (file.directoryExist("/proc"))
                  {
                    FILE *pfinPipe = NULL;
                    struct utsname server;
                    // {{{ process
                    if (strAction == "process")
                    {
                      string strProcess;
                      ssLine >> strProcess;
                      if (!strProcess.empty())
                      {
                        list<string> procList;
                        stringstream ssDetails;
                        process tProcess;
                        // {{{ gather process data
                        tProcess.nProcesses = 0;
                        tProcess.ulImage = 0;
                        tProcess.ulRealMinImage = 0;
                        tProcess.ulRealMaxImage = 0;
                        tProcess.ulResident = 0;
                        tProcess.ulRealMinResident = 0;
                        tProcess.ulRealMaxResident = 0;
                        tProcess.CStartTime = 0;
                        file.directoryList("/proc", procList);
                        for (list<string>::iterator i = procList.begin(); i != procList.end(); i++)
                        {
                          if ((*i)[0] != '.' && manip.isNumeric(*i) && file.directoryExist((string)"/proc/" + (*i)))
                          {
                            // {{{ linux
                            #ifdef LINUX
                            struct stat tStat;
                            struct passwd *ptPasswd = NULL;
                            if (stat(((string)"/proc/" + (*i)).c_str(), &tStat) == 0 && file.fileExist((string)"/proc/" + (*i) + (string)"/stat") && (ptPasswd = getpwuid(tStat.st_uid)) != NULL)
                            {
                              string strOwner = ptPasswd->pw_name;
                              ifstream inStat(((string)"/proc/" + (*i) + (string)"/stat").c_str());
                              if (inStat.good())
                              {
                                string strTemp, strDaemon;
                                long lPageSize = sysconf(_SC_PAGE_SIZE) / 1024;
                                unsigned long ulImage = 0, ulResident = 0;
                                inStat >> strTemp >> strDaemon;
                                for (unsigned int i = 0; i < 20; i++)
                                {
                                  inStat >> strTemp;
                                }
                                inStat >> ulImage >> ulResident;
                                ulImage /= 1024;
                                ulResident *= lPageSize;
                                if (!strDaemon.empty() && strDaemon[0] == '(')
                                {
                                  strDaemon.erase(0, 1);
                                }
                                if (!strDaemon.empty() && strDaemon[strDaemon.size() - 1] == ')')
                                {
                                  strDaemon.erase(strDaemon.size() - 1, 1);
                                }
                                if (strProcess == strDaemon)
                                {
                                  if (tProcess.owner.find(strOwner) == tProcess.owner.end())
                                  {
                                    tProcess.owner[strOwner] = 0;
                                  }
                                  tProcess.owner[strOwner]++;
                                  tProcess.nProcesses++;
                                  tProcess.ulImage += ulImage;
                                  if (tProcess.ulRealMinImage == 0 || ulImage < tProcess.ulRealMinImage)
                                  {
                                    tProcess.ulRealMinImage = ulImage;
                                  }
                                  if (tProcess.ulRealMaxImage == 0 || ulImage > tProcess.ulRealMaxImage)
                                  {
                                    tProcess.ulRealMaxImage = ulImage;
                                  }
                                  tProcess.ulResident += ulResident;
                                  if (tProcess.ulRealMinResident == 0 || ulResident < tProcess.ulRealMinResident)
                                  {
                                    tProcess.ulRealMinResident = ulResident;
                                  }
                                  if (tProcess.ulRealMaxResident == 0 || ulResident > tProcess.ulRealMaxResident)
                                  {
                                    tProcess.ulRealMaxResident = ulResident;
                                  }
                                  if ((pfinPipe = popen(((string)"ps --pid=" + (*i) + (string)" --format=lstart --no-headers").c_str(), "r")) != NULL)
                                  {
                                    char szTemp[4][10] = {"\0", "\0", "\0", "\0"};
                                    if (fscanf(pfinPipe, "%*s %s %s %s %s", szTemp[0], szTemp[1], szTemp[2], szTemp[3]) != EOF)
                                    {
                                      time_t CTime;
                                      struct tm tTime;
                                      tTime.tm_mon = (((string)szTemp[0] == "Jan")?0:((string)szTemp[0] == "Feb")?1:((string)szTemp[0] == "Mar")?2:((string)szTemp[0] == "Apr")?3:((string)szTemp[0] == "May")?4:((string)szTemp[0] == "Jun")?5:((string)szTemp[0] == "Jul")?6:((string)szTemp[0] == "Aug")?7:((string)szTemp[0] == "Sep")?8:((string)szTemp[0] == "Oct")?9:((string)szTemp[0] == "Nov")?10:((string)szTemp[0] == "Dec")?11:0);
                                      tTime.tm_mday = atoi(szTemp[1]);
                                      tTime.tm_year = atoi(szTemp[3]) - 1900;
                                      tTime.tm_hour = atoi((((string)szTemp[2]).substr(0, 2)).c_str());
                                      tTime.tm_min = atoi((((string)szTemp[2]).substr(3, 2)).c_str());
                                      tTime.tm_sec = atoi((((string)szTemp[2]).substr(6, 2)).c_str());
                                      tTime.tm_isdst = -1;
                                      CTime = mktime(&tTime);
                                      if (CTime > 0 && (tProcess.CStartTime == 0 || CTime < tProcess.CStartTime))
                                      {
                                        tProcess.CStartTime = CTime;
                                      }
                                    }
                                  }
                                  pclose(pfinPipe);
                                }
                              }
                              inStat.close();
                            }
                            #endif
                            // }}}
                            // {{{ solaris
                            #ifdef SOLARIS
                            if (file.fileExist((string)"/proc/" + (*i) + (string)"/psinfo"))
                            {
                              ifstream inProc(((string)"/proc/" + (*i) + (string)"/psinfo").c_str(), ios::in|ios::binary);
                              psinfo tPsInfo;
                              if (inProc.good() && inProc.read((char *)&tPsInfo, sizeof(psinfo)).good())
                              {
                                if (strProcess == (string)tPsInfo.pr_fname)
                                {
                                  string strOwner = getpwuid(tPsInfo.pr_uid)->pw_name;
                                  if (tProcess.owner.find(strOwner) == tProcess.owner.end())
                                  {
                                    tProcess.owner[strOwner] = 0;
                                  }
                                  tProcess.owner[strOwner]++;
                                  tProcess.nProcesses++;
                                  tProcess.ulImage += tPsInfo.pr_size;
                                  if (tProcess.ulRealMinImage == 0 || tPsInfo.pr_size < tProcess.ulRealMinImage)
                                  {
                                    tProcess.ulRealMinImage = tPsInfo.pr_size;
                                  }
                                  if (tProcess.ulRealMaxImage == 0 || tPsInfo.pr_size > tProcess.ulRealMaxImage)
                                  {
                                    tProcess.ulRealMaxImage = tPsInfo.pr_size;
                                  }
                                  tProcess.ulResident += tPsInfo.pr_rssize;
                                  if (tProcess.ulRealMinResident == 0 || tPsInfo.pr_rssize < tProcess.ulRealMinResident)
                                  {
                                    tProcess.ulRealMinResident = tPsInfo.pr_rssize;
                                  }
                                  if (tProcess.ulRealMaxResident == 0 || tPsInfo.pr_rssize > tProcess.ulRealMaxResident)
                                  {
                                    tProcess.ulRealMaxResident = tPsInfo.pr_rssize;
                                  }
                                  if (tProcess.CStartTime == 0 || tPsInfo.pr_start.tv_sec < tProcess.CStartTime)
                                  {
                                    tProcess.CStartTime = tPsInfo.pr_start.tv_sec;
                                  }
                                }
                              }
                              inProc.close();
                            }
                            #endif
                            // }}}
                          }
                        }
                        // }}}
                        procList.clear();
                        ssDetails << "process;";
                        ssDetails << strProcess << ';';
                        if (tProcess.CStartTime > 0)
                        {
                          struct tm *ptTime = localtime(&(tProcess.CStartTime));
                          ssDetails << setw(4) << setfill('0') << (ptTime->tm_year + 1900) << '-';
                          ssDetails << setw(2) << setfill('0') << (ptTime->tm_mon + 1) << '-';
                          ssDetails << setw(2) << setfill('0') << ptTime->tm_mday << ' ';
                          ssDetails << setw(2) << setfill('0') << ptTime->tm_hour << ':';
                          ssDetails << setw(2) << setfill('0') << ptTime->tm_min << ' ';
                          ssDetails << gstrTimezonePrefix << ((ptTime->tm_isdst)?'d':'s') << "t;";
                        }
                        else
                        {
                          ssDetails << ";";
                        }
                        for (map<string, unsigned int>::iterator i = tProcess.owner.begin(); i != tProcess.owner.end(); i++)
                        {
                          if (i != tProcess.owner.begin())
                          {
                            ssDetails << ',';
                          }
                          ssDetails << i->first << '=' << i->second;
                        }
                        ssDetails << ';';
                        ssDetails << tProcess.nProcesses << ';';
                        ssDetails << tProcess.ulImage << ';';
                        ssDetails << tProcess.ulRealMinImage << ';';
                        ssDetails << tProcess.ulRealMaxImage << ';';
                        ssDetails << tProcess.ulResident << ';';
                        ssDetails << tProcess.ulRealMinResident << ';';
                        ssDetails << tProcess.ulRealMaxResident;
                        strBuffer[1].append(ssDetails.str() + "\n");
                      }
                      else
                      {
                        strBuffer[1].append("process;;;;0;0;0;0;0;0;0\n");
                      }
                    }
                    // }}}
                    // {{{ script
                    else if (strAction == "script")
                    {
                      char *args[100], *pszArgument;
                      int readpipe[2] = {-1, -1}, writepipe[2] = {-1, -1};
                      pid_t childPid;
                      string strArgument, strCommand, strJson;
                      stringstream ssCommand;
                      unsigned int unIndex = 0;
                      gpUtility->getLine(ssLine, strCommand);
                      manip.trim(strCommand, strCommand);
                      ssCommand.str(strCommand);
                      while (ssCommand >> strArgument)
                      {
                        pszArgument = new char[strArgument.size() + 1];
                        strcpy(pszArgument, strArgument.c_str());
                        args[unIndex++] = pszArgument;
                      }
                      gpUtility->getLine(fdSocket, strJson);
                      manip.trim(strJson, strJson);
                      args[unIndex] = NULL;
                      if (pipe(readpipe) == 0)
                      {
                        if (pipe(writepipe) == 0)
                        {
                          if ((childPid = fork()) == 0)
                          {
                            int nReturn;
                            string strValue;
                            close(PARENT_WRITE);
                            close(PARENT_READ);
                            dup2(CHILD_READ, 0);
                            close(CHILD_READ);
                            dup2(CHILD_WRITE, 1);
                            close(CHILD_WRITE);
                            nReturn = execve(args[0], args, environ);
                            log((string)"Failed to execute " + strCommand + (string)" " + strJson + (string)" using execl() [" + manip.toString(nReturn, strValue) + (string)"]:  " + getErrorMessage(nReturn));
                            _exit(1);
                          }
                          else if (childPid > 0)
                          {
                            string strLine;
                            close(CHILD_READ);
                            close(CHILD_WRITE);
                            write(PARENT_WRITE, (strJson + (string)"\n").c_str(), strJson.size() + 1);
                            close(PARENT_READ);
                            close(PARENT_WRITE);
                          }
                          else
                          {
                            log((string)"Failed to fork process to system call.  " + (string)strerror(errno));
                          }
                        }
                        else
                        {
                          log((string)"Failed to establish write pipe to system call.  " + (string)strerror(errno));
                        }
                      }
                      else
                      {
                        log((string)"Failed to establish read pipe to system call.  " + (string)strerror(errno));
                      }
                      for (unsigned int i = 0; i < unIndex; i++)
                      {
                        delete args[i];
                      }
                    }
                    // }}}
                    // {{{ system
                    else if (strAction == "system")
                    {
                      map<string, bool> exclude;
                      stringstream ssDetails;
                      overall tOverall;
                      // {{{ gather system data
                      if (uname(&server) != -1)
                      {
                        // {{{ linux
                        #ifdef LINUX
                        struct sysinfo sys;
                        if (sysinfo(&sys) != -1)
                        {
                          ifstream inCpuSpeed("/proc/cpuinfo");
                          if (inCpuSpeed.good())
                          {
                            if ((pfinPipe = popen("top -b -n 1 | sed -n '8,$p'| awk '{print $9, $12}'", "r")) != NULL)
                            {
                              float fCpuSpeed = 0;
                              string strTemp;
                              while (fCpuSpeed == 0 && file.findLine(inCpuSpeed, false, false, "cpu MHz"))
                              {
                                inCpuSpeed >> strTemp >> strTemp >> strTemp >> fCpuSpeed;
                              }
                              tOverall.strOperatingSystem = server.sysname;
                              tOverall.strSystemRelease = server.release;
                              tOverall.nProcessors = get_nprocs();
                              tOverall.unCpuSpeed = ((tOverall.nProcessors > 0)?(unsigned int)fCpuSpeed:0);
                              tOverall.usProcesses = sys.procs;
                              char szProcess[32] = "\0";
                              float fCpu = 0, fCpuUsage = 0;
                              map<float, list<string> > load;
                              while (fscanf(pfinPipe, "%f %s%*[^\n]", &fCpu, &szProcess[0]) != EOF)
                              {
                                fCpuUsage += fCpu;
                                if (load.find(fCpu) == load.end())
                                {
                                  list<string> item;
                                  load[fCpu] = item;
                                }
                                if (load.find(fCpu) != load.end())
                                {
                                  load[fCpu].push_back(szProcess);
                                }
                              }
                              tOverall.unCpuUsage = (unsigned int)(fCpuUsage / ((tOverall.nProcessors > 0)?tOverall.nProcessors:1));
                              while (load.size() > 5)
                              {
                                load.begin()->second.clear();
                                load.erase(load.begin()->first);
                              }
                              for (map<float, list<string> >::iterator i = load.begin(); i != load.end(); i++)
                              {
                                for (list<string>::iterator j = i->second.begin(); j != i->second.end(); j++)
                                {
                                  stringstream ssCpuProcessUsage;
                                  ssCpuProcessUsage << (*j) << '=' << i->first;
                                  if (!tOverall.strCpuProcessUsage.empty())
                                  {
                                    ssCpuProcessUsage << ',';
                                  }
                                  tOverall.strCpuProcessUsage = ssCpuProcessUsage.str() + tOverall.strCpuProcessUsage;
                                }
                                i->second.clear();
                              }
                              load.clear();
                              tOverall.lUpTime = sys.uptime / 86400;
                              tOverall.ulMainTotal = (sys.totalram * sys.mem_unit) / 1048576;
                              tOverall.ulMainUsed = ((sys.totalram - sys.freeram) * sys.mem_unit) / 1048576;
                              tOverall.ulSwapTotal = (sys.totalswap * sys.mem_unit) / 1048576;
                              tOverall.ulSwapUsed = ((sys.totalswap - sys.freeswap) * sys.mem_unit) / 1048576;
                            }
                            pclose(pfinPipe);
                          }
                          inCpuSpeed.close();
                        }
                        #endif
                        // }}}
                        // {{{ solaris
                        #ifdef SOLARIS
                        tOverall.strOperatingSystem = server.sysname;
                        tOverall.strSystemRelease = server.release;
                        tOverall.nProcessors = (int)sysconf(_SC_NPROCESSORS_CONF);
                        kstat_ctl_t *kc;
                        kstat_t *sys_pagesp;
                        size_t lIdle, lKernel, lUser;
                        kstat_named_t *kn;
                        kc = kstat_open();
                        if (kc != NULL && (sys_pagesp = kstat_lookup(kc, "cpu_info", 0, "cpu_info0")) != NULL)
                        {
                          kstat_read(kc, sys_pagesp, 0);
                          kn = (kstat_named_t *)kstat_data_lookup(sys_pagesp, "clock_MHz");
                          tOverall.unCpuSpeed = (unsigned int)kn->value.ul;
                        }
                        list<string> dirList;
                        file.directoryList("/proc/", dirList);
                        unsigned short usProcesses = ((dirList.size() >= 2)?dirList.size() - 2:0);
                        dirList.clear();
                        tOverall.usProcesses = usProcesses;
                        if (kc != NULL && (sys_pagesp = kstat_lookup(kc, "cpu", 0, "sys")) != NULL)
                        {
                          kstat_read(kc, sys_pagesp, 0);
                          kn = (kstat_named_t *)kstat_data_lookup(sys_pagesp, "cpu_nsec_idle");
                          lIdle = kn->value.ul;
                          kn = (kstat_named_t *)kstat_data_lookup(sys_pagesp, "cpu_nsec_kernel");
                          lKernel = kn->value.ul;
                          kn = (kstat_named_t *)kstat_data_lookup(sys_pagesp, "cpu_nsec_user");
                          lUser = kn->value.ul;
                          tOverall.unCpuUsage = (unsigned int)((lKernel + lUser) * 100 / (lIdle + lKernel + lUser));
                        }
                        kstat_close(kc);
                        if (file.fileExist("/proc/0/psinfo"))
                        {
                          ifstream inProc("/proc/0/psinfo", ios::in|ios::binary);
                          psinfo tPsInfo;
                          if (inProc.good() && inProc.read((char *)&tPsInfo, sizeof(psinfo)).good())
                          {
                            time_t CTime;
                            tOverall.lUpTime = (unsigned long)((time(&CTime) - tPsInfo.pr_start.tv_sec) / 60 /60 / 24);
                          }
                          inProc.close();
                        }
                        long lPageSize = sysconf(_SC_PAGESIZE);
                        tOverall.ulMainTotal = (unsigned long)((float)lPageSize / 1024 / 1024 * sysconf(_SC_PHYS_PAGES));
                        tOverall.ulMainUsed = (unsigned long)(tOverall.ulMainTotal - ((float)lPageSize / 1024 / 1024 * sysconf(_SC_AVPHYS_PAGES)));
                        int nNum, nSwapCount;
                        char szDummyBuffer[MAX_SWAP_ENTRIES][80];
                        swapdata tSwapt;
                        tSwapt.tblcount = MAX_SWAP_ENTRIES;
                        for (unsigned int i = 0; i < MAX_SWAP_ENTRIES; i++)
                        {
                          tSwapt.swapdat[i].ste_path = szDummyBuffer[i]; 
                        }
                        nNum = swapctl(SC_GETNSWP, 0);
                        nSwapCount = swapctl(SC_LIST, (void *)&tSwapt);
                        if (nSwapCount != -1 && nNum != -1)
                        {
                          unsigned long ulPageTotal = 0, ulPageFree = 0;
                          for (int i = 0; i < nSwapCount; i++)
                          {
                            ulPageTotal += tSwapt.swapdat[i].ste_pages;
                            ulPageFree += tSwapt.swapdat[i].ste_free;
                          }
                          tOverall.ulSwapTotal = (unsigned long)((float)lPageSize / 1024 / 1024 * ulPageTotal);
                          tOverall.ulSwapUsed = (unsigned long)(tOverall.ulSwapTotal - ((float)lPageSize / 1024 / 1024 * ulPageFree));
                        }
                        #endif
                        // }}}
                      }
                      // }}}
                      ssDetails << "system;";
                      ssDetails << tOverall.strOperatingSystem << ';';
                      ssDetails << tOverall.strSystemRelease << ';';
                      ssDetails << tOverall.nProcessors << ';';
                      ssDetails << tOverall.unCpuSpeed << ';';
                      ssDetails << tOverall.usProcesses << ';';
                      ssDetails << tOverall.unCpuUsage;
                      if (!tOverall.strCpuProcessUsage.empty())
                      {
                        ssDetails << "|" << tOverall.strCpuProcessUsage;
                      }
                      ssDetails << ';';
                      ssDetails << tOverall.lUpTime << ';';
                      ssDetails << tOverall.ulMainUsed << ';';
                      ssDetails << tOverall.ulMainTotal << ';';
                      ssDetails << tOverall.ulSwapUsed << ';';
                      ssDetails << tOverall.ulSwapTotal << ';';
                      #ifdef SOLARIS
                      if ((pfinPipe = popen("/usr/sbin/df -ln", "r")) != NULL)
                      {
                        char szBuffer[1024] = "\0";
                        while (fgets(szBuffer, 1023, pfinPipe) != NULL)
                        {
                          string strName, strType;
                          stringstream ssBuffer(szBuffer);
                          getline(ssBuffer, strName, ':');
                          manip.trim(strName, strName);
                          getline(ssBuffer, strType, ':');
                          manip.trim(strType, strType);
                          if (strType == "lofs")
                          {
                            exclude[strName] = true;
                          }
                        }
                        pclose(pfinPipe);
                      }
                      #endif
                      if ((pfinPipe = popen("df -kl", "r")) != NULL)
                      {
                        bool bFirst = true;
                        char szField[3][128] = {"\0", "\0", "\0"};
                        fscanf(pfinPipe, "%*s %s %*s %*s %s %s %*s", szField[0], szField[1], szField[2]);
                        while (fscanf(pfinPipe, "%*s %s %*s %*s %s %s", szField[0], szField[1], szField[2]) != EOF)
                        {
                          if (atoi(szField[0]) > 0 && exclude.find(szField[2]) == exclude.end())
                          {
                            string strUsage = szField[1];
                            strUsage.erase(strUsage.size() - 1, 1);
                            if (bFirst)
                            {
                              bFirst = false;
                            }
                            else
                            {
                              ssDetails << ',';
                            }
                            ssDetails << szField[2] << '=' << strUsage;
                          }
                        }
                      }
                      if (pfinPipe)
                      {
                        pclose(pfinPipe);
                      }
                      else
                      {
                        cout<<"Error("<<errno<<"): "<<strerror(errno)<<endl;
                      }
                      exclude.clear();
                      strBuffer[1].append(ssDetails.str() + "\n");
                    }
                    // }}}
                  }
                }
              }
              else
              {
                bExit = true;
              }
            }
            if (fds[0].revents & POLLOUT)
            {
              if (!gpUtility->sslWrite(ssl, strBuffer[1], nReturn))
              {
                bExit = true;
              }
            }
          }
          else if (nReturn < 0)
          {
            bExit = true;
          }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fdSocket);
      }
      sleep(300);
    }
    if (ctx != NULL)
    {
      SSL_CTX_free(ctx);
    }
    gpUtility->sslDeinit();
  }
  // }}}
  // {{{ usage statement
  else
  {
    mUSAGE(argv[0]);
  }
  // }}}
  delete gpUtility;

  return 0;
}
// }}}
// {{{ getErrorMessage()
string getErrorMessage(const int nError)
{
  string strReturn;

  switch (nError)
  {
    #ifdef EACCES
    case EACCES : strReturn = "EACCES Permission denied"; break;
    #endif
    #ifdef EPERM
    case EPERM : strReturn = "EPERM Not super-user"; break;
    #endif
    #ifdef E2BIG
    case E2BIG : strReturn = "E2BIG Arg list too long"; break;
    #endif
    #ifdef ENOEXEC
    case ENOEXEC : strReturn = "ENOEXEC Exec format error"; break;
    #endif
    #ifdef EFAULT
    case EFAULT : strReturn = "EFAULT Bad address"; break;
    #endif
    #ifdef ENAMETOOLONG
    case ENAMETOOLONG : strReturn = "ENAMETOOLONG path name is too long"; break;
    #endif
    #ifdef ENOENT
    case ENOENT : strReturn = "ENOENT No such file or directory"; break;
    #endif
    #ifdef ENOMEM
    case ENOMEM : strReturn = "ENOMEM Not enough core"; break;
    #endif
    #ifdef ENOTDIR
    case ENOTDIR : strReturn = "ENOTDIR Not a directory"; break;
    #endif
    #ifdef ELOOP
    case ELOOP : strReturn = "ELOOP Too many symbolic links"; break;
    #endif
    #ifdef ETXTBSY
    case ETXTBSY : strReturn = "ETXTBSY Text file busy"; break;
    #endif
    #ifdef EIO
    case EIO : strReturn = "EIO I/O error"; break;
    #endif
    #ifdef ENFILE
    case ENFILE : strReturn = "ENFILE Too many open files in system"; break;
    #endif
    #ifdef EINVAL
    case EINVAL : strReturn = "EINVAL Invalid argument"; break;
    #endif
    #ifdef EISDIR
    case EISDIR : strReturn = "EISDIR Is a directory"; break;
    #endif
    #ifdef ELIBBAD
    case ELIBBAD : strReturn = "ELIBBAD Accessing a corrupted shared lib"; break;
    #endif
    default : strReturn = strerror(nError); break;
  }

  return strReturn;
}
// }}}
// {{{ log()
void log(const string strMessage)
{
  ofstream outLog;
  StringManip manip;

  outLog.open(LOG, ios::out|ios::app);
  if (outLog.good())
  {
    time_t CTime;
    char szTimeStamp[256] = "\0";
    struct tm *tTime;
    time(&CTime);
    if ((tTime = localtime(&CTime)))
    {
      strftime(szTimeStamp, 17, "%Y-%m-%d %H:%M", tTime);
    }
    else
    {
      strcpy(szTimeStamp, "................");
    }
    outLog << szTimeStamp << " ---> "<< strMessage << endl;
    delete tTime;
  }
  outLog.close();
}
// }}}
// {{{ sighandle()
void sighandle(const int nSignal)
{
  stringstream ssCore;

  sethandles(sigdummy);
  if (nSignal != SIGINT && nSignal != SIGTERM)
  {
    ssCore << "gcore " << getpid() << " >/dev/null 2>&1";
    system(ssCore.str().c_str());
  }
  exit(1);
}
// }}}
