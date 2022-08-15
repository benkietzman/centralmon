// vim600: fdm=marker
/* -*- c++ -*- */
///////////////////////////////////////////
// Central Monitor:  centralmond
// -------------------------------------
// file       : centralmond.cpp
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

/*! \file centralmond.cpp
* \brief Central Monitor Server Daemon
*
* Analyzes and acts upon system information.
*/
// {{{ includes
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
using namespace std;
#include <Central>
#include <Json>
#include <ServiceJunction>
#include <SignalHandling>
#include <Syslog>
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
#define mUSAGE(A) cout << endl << "Usage:  "<< A << " [options]"  << endl << endl << " --central=CENTRAL" << endl << "     Provides the path to the central file." << endl << endl << " --certificate=CERTIFICATE" << endl << "     Provides the path to the certificate file." << endl << endl << " -c CREDENTIALS, --cred=CREDENTIALS" << endl << "     Provides the path to the credentials file." << endl << endl << " -d, --daemon" << endl << "     Turns the process into a daemon." << endl << endl << " -e EMAIL, --email=EMAIL" << endl << "     Provides the email address for default notifications." << endl << endl << " -h, --help" << endl << "     Displays this usage screen." << endl << endl << " --private-key=PRIVATE_KEY" << endl << "     Provides the path to the private key file." << endl << endl << " -r ROOM, --room=ROOM" << endl << "     Provides the chat room." << endl << endl << "     --syslog" << endl << "     Enables syslog." << endl << endl << " -v, --version" << endl << "     Displays the current version of this software." << endl << endl
/*! \def mVER_USAGE(A,B)
* \brief Prints the version number.
*/
#define mVER_USAGE(A,B) cout << endl << A << " Version: " << B << endl << endl
/*! \def PORT
* \brief Supplies the status communication port.
*/
#define PORT "4636"
// }}}
// {{{ structs
struct connection
{
  bool bClient;
  bool bClose;
  int fdData;
  string strBuffer[2];
  string strServer;
  time_t CStartTime;
  time_t CEndTime;
  SSL *ssl;
  common_socket_type eSocketType;
};
struct message
{
  bool bEnabled;
  time_t CStartTime;
  time_t CEndTime;
  string strApplication;
  string strMessage;
  string strType;
};
struct process
{
  bool bChecking;
  bool bHaveValues;
  bool bPage;
  bool bPrevPage;
  int fdScket;
  int nDelay;
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
  time_t CTime;
  map<string, unsigned int> owner;
  string strApplicationServerID;
  string strStartTime;
  string strOwner;
  string strScript;
  stringstream ssAlarms;
  stringstream ssPrevAlarms;
};
struct overall
{
  bool bHaveThresholds;
  bool bHaveValues;
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
  map<string, unsigned int> partition;
  string strCpuProcessUsage;
  string strOperatingSystem;
  string strPartitions;
  string strSystemRelease;
  stringstream ssAlarms;
  stringstream ssPrevAlarms;
  map<string, process *> processList;
};
// }}}
// {{{ global variables
static bool gbDaemon = false; //!< Global daemon variable.
static bool gbShutdown = false; //!< Global shutdown variable.
static int gfdStatus; //!< Global socket descriptor.
static list<message *> gMessageList; //!< Contains the message list.
static map<string, string> gCred; //!< Contains the Bridge credentials.
static map<string, overall *> gOverallList; //!< Contains the overall list.
static string gstrApplication = "Central Monitor"; //!< Global application name.
static string gstrEmail; //!< Global notification email address.
static string gstrRoom; //!< Global chat room.
static string gstrTimezonePrefix = "c"; //!< Contains the local timezone.
static Central *gpCentral = NULL; //!< Contains the Central class.
static ServiceJunction *gpJunction = NULL; //!< Contains the Service Junction class.
static Syslog *gpSyslog = NULL; //!< Contains the Syslog class.
// }}}
// {{{ prototypes
/*! \fn bool authorizedClient(const string strServer, const string strClient)
* \brief Checks for authorized client connection.
* \param strServer Contains the client server name.
* \param strClient Contains the client IP address.
*/
bool authorizedClient(const string strServer, const string strClient);
/*! \fn bool chat(const string strMessage, string &strError)
* \brief Sends a chat message to the Bridge.
* \param strMessage Contains the message.
* \param strError Contains the returned error.
* \return Returns a boolean true/false value.
*/
bool chat(const string strMessage, string &strError);
/*! \fn bool notify(const string strMessage, string &strError)
* \brief Notifies the email box.
* \param strMessage Contains the message.
* \param strError Contains the returned error.
* \return Returns a boolean true/false value.
*/
bool notify(const string strMessage, string &strError);
/*! \fn void notifyApplicationContact(const string strServer, const string strProcess)
* \brief Notifies application contacts.
* \param strServer Contains the server name.
* \param strProcess Contains the process name.
*/
void notifyApplicationContact(const string strServer, const string strProcess);
/*! \fn void notifyServerContact(const string strServer)
* \param strServer Contains the server name.
* \brief Notifies server contacts.
*/
void notifyServerContact(const string strServer);
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
  bool bSetCredentials = false;
  string strCertificate, strCred, strError, strPrivateKey;
  SSL_CTX *ctx = NULL;

  gpCentral = new Central(strError);
  gpJunction = new ServiceJunction(strError);
  // {{{ set signal handling
  sethandles(sighandle);
  signal(SIGBUS, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGSEGV, SIG_IGN);
  signal(SIGWINCH, SIG_IGN);
  // }}}
  // {{{ command line arguments
  for (int i = 1; i < argc; i++)
  {
    string strArg = argv[i];
    if (strArg.size() > 10 && strArg.substr(0, 10) == "--central=")
    {
      string strCentral = strArg.substr(10, strArg.size() - 10);
      gpCentral->manip()->purgeChar(strCentral, strCentral, "'");
      gpCentral->manip()->purgeChar(strCentral, strCentral, "\"");
      gpCentral->acorn()->utility()->setConfPath(strCentral, strError);
      gpCentral->junction()->utility()->setConfPath(strCentral, strError);
      gpCentral->utility()->setConfPath(strCentral, strError);
      gpJunction->utility()->setConfPath(strCentral, strError);
    }
    else if (strArg.size() > 14 && strArg.substr(0, 14) == "--certificate=")
    {
      strCertificate = strArg.substr(14, strArg.size() - 14);
      gpCentral->manip()->purgeChar(strCertificate, strCertificate, "'");
      gpCentral->manip()->purgeChar(strCertificate, strCertificate, "\"");
    }
    else if (strArg == "-c" || (strArg.size() > 7 && strArg.substr(0, 7) == "--cred="))
    {
      if (strArg == "-c" && i + 1 < argc && argv[i+1][0] != '-')
      {
        strCred = argv[++i];
      }
      else
      {
        strCred = strArg.substr(7, strArg.size() - 7);
      }
      gpCentral->manip()->purgeChar(strCred, strCred, "'");
      gpCentral->manip()->purgeChar(strCred, strCred, "\"");
    }
    else if (strArg == "-d" || strArg == "--daemon")
    {
      gbDaemon = true;
    }
    else if (strArg == "-e" || (strArg.size() > 8 && strArg.substr(0, 8) == "--email="))
    {
      if (strArg == "-e" && i + 1 < argc && argv[i+1][0] != '-')
      {
        gstrEmail = argv[++i];
      }
      else
      {
        gstrEmail = strArg.substr(8, strArg.size() - 8);
      }
      gpCentral->manip()->purgeChar(gstrEmail, gstrEmail, "'");
      gpCentral->manip()->purgeChar(gstrEmail, gstrEmail, "\"");
    }
    else if (strArg == "-h" || strArg == "--help")
    {
      mUSAGE(argv[0]);
      return 0;
    }
    else if (strArg.size() > 14 && strArg.substr(0, 14) == "--private-key=")
    {
      strPrivateKey = strArg.substr(14, strArg.size() - 14);
      gpCentral->manip()->purgeChar(strPrivateKey, strPrivateKey, "'");
      gpCentral->manip()->purgeChar(strPrivateKey, strPrivateKey, "\"");
    }
    else if (strArg == "-r" || (strArg.size() > 7 && strArg.substr(0, 7) == "--room="))
    {
      if (strArg == "-r" && i + 1 < argc && argv[i+1][0] != '-')
      {
        gstrRoom = argv[++i];
      }
      else
      {
        gstrRoom = strArg.substr(7, strArg.size() - 7);
      }
      gpCentral->manip()->purgeChar(gstrRoom, gstrRoom, "'");
      gpCentral->manip()->purgeChar(gstrRoom, gstrRoom, "\"");
    }
    else if (strArg == "--syslog")
    {
      gpSyslog = new Syslog(gstrApplication, "centralmond");
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
  gpCentral->setApplication(gstrApplication);
  gpCentral->setEmail(gstrEmail);
  gpJunction->setApplication(gstrApplication);
  if (!gstrRoom.empty())
  {
    if (gstrRoom[0] != '#')
    {
      gstrRoom = (string)"#" + gstrRoom;
    }
    gpCentral->setRoom(gstrRoom);
  }
  if (!strCred.empty())
  {
    ifstream inCred((strCred).c_str());
    if (inCred.good()) 
    {
      string strLine;
      while (gpCentral->utility()->getLine(inCred, strLine))
      {
        Json *ptJson = new Json(strLine);
        if (ptJson->m.find("bridge") != ptJson->m.end())
        {
          ptJson->m["bridge"]->flatten(gCred, true, false);
          if (ptJson->m.find("central") != ptJson->m.end())
          {
            map<string, string> cred;
            ptJson->m["central"]->flatten(cred, true, false);
            cred["Type"] = "mysql";
            if (gpCentral->addDatabase("central", cred, strError))
            {
              bSetCredentials = true;
            }
            cred.clear();
          }
        }
        delete ptJson;
      }
    }
    inCred.close();
  }
  gpCentral->utility()->sslInit();
  if (!strCertificate.empty() && !strPrivateKey.empty() && (ctx = gpCentral->utility()->sslInitServer(strCertificate, strPrivateKey, strError)) == NULL)
  {
    cerr << "Central::utility()->sslInitServer() error:  " << strError << endl;
  }
  // {{{ normal run
  if (!gstrEmail.empty() && bSetCredentials && ctx != NULL)
  {
    ifstream inFile;
    socklen_t clilen;
    sockaddr_in cli_addr;
    struct addrinfo hints;
    struct addrinfo *result;
    int nReturn;
    if (gbDaemon)
    {
      gpCentral->utility()->daemonize();
    }
    // {{{ determine timezone prefix
    inFile.open("/etc/TIMEZONE");
    if (inFile.good())
    {
      bool bDone = false;
      string strLine;
      while (!bDone && gpCentral->utility()->getLine(inFile, strLine))
      {
        gpCentral->manip()->trim(strLine, strLine);
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
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((nReturn = getaddrinfo(NULL, PORT, &hints, &result)) == 0)
    {
      bool bBound = false;
      struct addrinfo *rp;
      for (rp = result; !bBound && rp != NULL; rp = rp->ai_next)
      {
        if ((gfdStatus = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) >= 0)
        {
          int nOn = 1;
          setsockopt(gfdStatus, SOL_SOCKET, SO_REUSEADDR, (char *)&nOn, sizeof(nOn));
          if (bind(gfdStatus, rp->ai_addr, rp->ai_addrlen) == 0)
          {
            bBound = true;
          }
          else
          {
            close(gfdStatus);
          }
        }
      }
      freeaddrinfo(result);
      if (bBound)
      {
        if (listen(gfdStatus, 50) == 0)
        {
          bool bExit = false;
          list<connection *> bridge;
          pollfd *fds;
          size_t unIndex;
          stringstream ssMessage;
          clilen = sizeof(cli_addr);
          while (!gbShutdown && !bExit)
          {
            fds = new pollfd[bridge.size()+1];
            unIndex = 0;
            fds[unIndex].fd = gfdStatus;
            fds[unIndex].events = POLLIN;
            unIndex++;
            for (list<connection *>::iterator i = bridge.begin(); i != bridge.end(); i++)
            {
              fds[unIndex].fd = (*i)->fdData;
              fds[unIndex].events = POLLIN;
              if (!(*i)->strBuffer[1].empty())
              {
                fds[unIndex].events |= POLLOUT;
              }
              unIndex++;
            }
            if ((nReturn = poll(fds, unIndex, 250)) > 0)
            {
              bool bSync = false;
              time_t CTime;
              list<list<connection *>::iterator> removeList;
              if (fds[0].revents & POLLIN)
              {
                int fdData;
                if ((fdData = accept(gfdStatus, (struct sockaddr *)&cli_addr, &clilen)) >= 0)
                {
                  connection *ptConnection = new connection;
                  if (gpSyslog != NULL)
                  {
                    gpSyslog->connectionStarted("Accepted an incoming request.", fdData);
                  }
                  ptConnection->bClient = false;
                  ptConnection->bClose = false;
                  ptConnection->fdData = fdData;
                  ptConnection->ssl = NULL;
                  ptConnection->eSocketType = COMMON_SOCKET_UNKNOWN;
                  bridge.push_back(ptConnection);
                }
                else
                {
                  bExit = true;
                }
              }
              time(&CTime);
              for (size_t i = 1; i < unIndex; i++)
              {
                bool bFound = false;
                for (list<connection *>::iterator j = bridge.begin(); !bFound && j != bridge.end(); j++)
                {
                  if (fds[i].fd == (*j)->fdData)
                  {
                    overall *ptOverall = NULL;
                    bFound = true;
                    if ((*j)->bClient && gOverallList.find((*j)->strServer) != gOverallList.end())
                    {
                      ptOverall = gOverallList[(*j)->strServer];
                    }
                    if (fds[i].revents & POLLIN)
                    {
                      if ((*j)->eSocketType == COMMON_SOCKET_UNKNOWN)
                      {
                        if (gpCentral->utility()->socketType((*j)->fdData, (*j)->eSocketType, strError))
                        {
                          if ((*j)->eSocketType == COMMON_SOCKET_ENCRYPTED && ((*j)->ssl = gpCentral->utility()->sslAccept(ctx, (*j)->fdData, strError)) == NULL)
                          {
                            (*j)->bClose = true;
                          }
                        }
                        else
                        {
                          (*j)->bClose = true;
                        }
                      }
                      if (!(*j)->bClose && (((*j)->eSocketType == COMMON_SOCKET_ENCRYPTED && gpCentral->utility()->sslRead((*j)->ssl, (*j)->strBuffer[0], nReturn)) || ((*j)->eSocketType == COMMON_SOCKET_UNENCRYPTED && gpCentral->utility()->fdRead((*j)->fdData, (*j)->strBuffer[0], nReturn))))
                      {
                        size_t nPosition;
                        while ((nPosition = (*j)->strBuffer[0].find("\n")) != string::npos)
                        {
                          string strAction, strLine = (*j)->strBuffer[0].substr(0, nPosition);
                          (*j)->strBuffer[0].erase(0, nPosition + 1);
                          if ((*j)->bClient)
                          {
                            gpCentral->manip()->getToken(strAction, strLine, 1, ";");
                            // {{{ process
                            if (strAction == "process")
                            {
                              string strProcess;
                              if (!gpCentral->manip()->getToken(strProcess, strLine, 2, ";").empty())
                              {
                                string strToken, strOwners, strOwner, strCount;
                                if (ptOverall != NULL && ptOverall->processList.find(strProcess) != ptOverall->processList.end())
                                {
                                  ptOverall->processList[strProcess]->strStartTime = gpCentral->manip()->getToken(strToken, strLine, 3, ";");
                                  ptOverall->processList[strProcess]->owner.clear();
                                  gpCentral->manip()->getToken(strOwners, strLine, 4, ";");
                                  for (int k = 1; !gpCentral->manip()->getToken(strToken, strOwners, k, ",", true).empty(); k++)
                                  {
                                    if (!gpCentral->manip()->getToken(strOwner, strToken, 1, "=").empty())
                                    {
                                      ptOverall->processList[strProcess]->owner[strOwner] = (unsigned int)atoi(gpCentral->manip()->getToken(strCount, strToken, 2, "=").c_str());
                                    }
                                  }
                                  ptOverall->processList[strProcess]->nProcesses = atoi(gpCentral->manip()->getToken(strToken, strLine, 5, ";").c_str());
                                  ptOverall->processList[strProcess]->ulImage = atol(gpCentral->manip()->getToken(strToken, strLine, 6, ";").c_str());
                                  ptOverall->processList[strProcess]->ulRealMinImage = atol(gpCentral->manip()->getToken(strToken, strLine, 7, ";").c_str());
                                  ptOverall->processList[strProcess]->ulRealMaxImage = atol(gpCentral->manip()->getToken(strToken, strLine, 8, ";").c_str());
                                  ptOverall->processList[strProcess]->ulResident = atol(gpCentral->manip()->getToken(strToken, strLine, 9, ";").c_str());
                                  ptOverall->processList[strProcess]->ulRealMinResident = atol(gpCentral->manip()->getToken(strToken, strLine, 10, ";").c_str());
                                  ptOverall->processList[strProcess]->ulRealMaxResident = atol(gpCentral->manip()->getToken(strToken, strLine, 11, ";").c_str());
                                  if (ptOverall->processList[strProcess]->nProcesses <= 0)
                                  {
                                    if (ptOverall->processList[strProcess]->CTime <= 0)
                                    {
                                      time(&(ptOverall->processList[strProcess]->CTime));
                                    }
                                  }
                                  else
                                  {
                                    ptOverall->processList[strProcess]->CTime = 0;
                                  }
                                  ptOverall->processList[strProcess]->bHaveValues = true;
                                  // {{{ write out process alarm information
                                  ptOverall->processList[strProcess]->bPage = false;
                                  ptOverall->processList[strProcess]->ssAlarms.str("");
                                  if (ptOverall->processList[strProcess]->nProcesses <= 0)
                                  {
                                    time_t CTime;
                                    time(&CTime);
                                    if (ptOverall->processList[strProcess]->nDelay <= 0 || (ptOverall->processList[strProcess]->CTime > 0 && CTime - ptOverall->processList[strProcess]->CTime >= ptOverall->processList[strProcess]->nDelay))
                                    {
                                      ptOverall->processList[strProcess]->bPage = true;
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " is not currently running";
                                    }
                                  }
                                  else
                                  {
                                    if (!ptOverall->processList[strProcess]->strOwner.empty())
                                    {
                                      bool bFoundOwner = false;
                                      for (map<string, unsigned int>::iterator k = ptOverall->processList[strProcess]->owner.begin(); !bFoundOwner && k != ptOverall->processList[strProcess]->owner.end(); k++)
                                      {
                                        if (ptOverall->processList[strProcess]->strOwner == k->first)
                                        {
                                          bFoundOwner = true;
                                        }
                                      }
                                      if (!bFoundOwner)
                                      {
                                        ptOverall->processList[strProcess]->bPage = true;
                                        ptOverall->processList[strProcess]->ssAlarms << strProcess << " is not running under the required " << ptOverall->processList[strProcess]->strOwner << " account";
                                      }
                                    }
                                    if (ptOverall->processList[strProcess]->nMinProcesses > 0 && ptOverall->processList[strProcess]->nProcesses < ptOverall->processList[strProcess]->nMinProcesses)
                                    {
                                      if (!ptOverall->processList[strProcess]->ssAlarms.str().empty())
                                      {
                                        ptOverall->processList[strProcess]->ssAlarms << ",";
                                      }
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " is running " << ptOverall->processList[strProcess]->nProcesses << " processes which is less than the minimum " << ptOverall->processList[strProcess]->nMinProcesses << " processes";
                                    }
                                    else if (ptOverall->processList[strProcess]->nMaxProcesses > 0 && ptOverall->processList[strProcess]->nProcesses > ptOverall->processList[strProcess]->nMaxProcesses)
                                    {
                                      if (!ptOverall->processList[strProcess]->ssAlarms.str().empty())
                                      {
                                        ptOverall->processList[strProcess]->ssAlarms << ",";
                                      }
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " is running " << ptOverall->processList[strProcess]->nProcesses << " processes which is more than the maximum " << ptOverall->processList[strProcess]->nMaxProcesses << " processes";
                                    }
                                    if (ptOverall->processList[strProcess]->ulMinImage > 0 && ptOverall->processList[strProcess]->ulRealMinImage < ptOverall->processList[strProcess]->ulMinImage)
                                    {
                                      if (!ptOverall->processList[strProcess]->ssAlarms.str().empty())
                                      {
                                        ptOverall->processList[strProcess]->ssAlarms << ",";
                                      }
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " has an image size of " << ptOverall->processList[strProcess]->ulRealMinImage << "KB which is less than the minimum " << ptOverall->processList[strProcess]->ulMinImage << "KB";
                                    }
                                    if (ptOverall->processList[strProcess]->ulMaxImage > 0 && ptOverall->processList[strProcess]->ulRealMaxImage > ptOverall->processList[strProcess]->ulMaxImage)
                                    {
                                      if (!ptOverall->processList[strProcess]->ssAlarms.str().empty())
                                      {
                                        ptOverall->processList[strProcess]->ssAlarms << ",";
                                      }
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " has an image size of " << ptOverall->processList[strProcess]->ulRealMaxImage << "KB which is more than the maximum " << ptOverall->processList[strProcess]->ulMaxImage << "KB";
                                    }
                                    if (ptOverall->processList[strProcess]->ulMinResident > 0 && ptOverall->processList[strProcess]->ulRealMinResident < ptOverall->processList[strProcess]->ulMinResident)
                                    {
                                      if (!ptOverall->processList[strProcess]->ssAlarms.str().empty())
                                      {
                                        ptOverall->processList[strProcess]->ssAlarms << ",";
                                      }
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " has a resident size of " << ptOverall->processList[strProcess]->ulRealMinResident << "KB which is less than the minimum " << ptOverall->processList[strProcess]->ulMinResident << "KB";
                                    }
                                    if (ptOverall->processList[strProcess]->ulMaxResident > 0 && ptOverall->processList[strProcess]->ulRealMaxResident > ptOverall->processList[strProcess]->ulMaxResident)
                                    {
                                      if (!ptOverall->processList[strProcess]->ssAlarms.str().empty())
                                      {
                                        ptOverall->processList[strProcess]->ssAlarms << ",";
                                      }
                                      ptOverall->processList[strProcess]->ssAlarms << strProcess << " has a resident size of " << ptOverall->processList[strProcess]->ulRealMaxResident << "KB which is more than the maximum " << ptOverall->processList[strProcess]->ulMaxResident << "KB";
                                    }
                                  }
                                  if (!ptOverall->processList[strProcess]->ssAlarms.str().empty() && (ptOverall->processList[strProcess]->ssPrevAlarms.str().empty() || (ptOverall->processList[strProcess]->bPage && !ptOverall->processList[strProcess]->bPrevPage)))
                                  {
                                    ptOverall->processList[strProcess]->bPrevPage = ptOverall->processList[strProcess]->bPage;
                                    ptOverall->processList[strProcess]->ssPrevAlarms << ptOverall->processList[strProcess]->ssAlarms.str();
                                    if (ptOverall->processList[strProcess]->strScript.empty())
                                    {
                                      notifyApplicationContact((*j)->strServer, strProcess);
                                    }
                                    else
                                    {
                                      list<string> contactList;
                                      string strValue;
                                      stringstream ssQuery, ssMessage;
                                      Json *ptJson = new Json;
                                      ptJson->insert("type", "process");
                                      ptJson->insert("daemon", strProcess);
                                      ptJson->insert("start", ptOverall->processList[strProcess]->strStartTime);
                                      ptJson->m["owner"] = new Json;
                                      for (map<string, unsigned int>::iterator k = ptOverall->processList[strProcess]->owner.begin(); k != ptOverall->processList[strProcess]->owner.end(); k++)
                                      {
                                        ptJson->m["owner"]->insert(k->first, gpCentral->manip()->toString(k->second, strValue));
                                      }
                                      ptJson->insert("processes", gpCentral->manip()->toString(ptOverall->processList[strProcess]->nProcesses, strValue));
                                      ptJson->insert("min_processes", gpCentral->manip()->toString(ptOverall->processList[strProcess]->nMinProcesses, strValue));
                                      ptJson->insert("max_processes", gpCentral->manip()->toString(ptOverall->processList[strProcess]->nMaxProcesses, strValue));
                                      ptJson->insert("image", gpCentral->manip()->toString(ptOverall->processList[strProcess]->ulImage, strValue));
                                      ptJson->insert("min_image", gpCentral->manip()->toString(ptOverall->processList[strProcess]->ulRealMinImage, strValue));
                                      ptJson->insert("max_image", gpCentral->manip()->toString(ptOverall->processList[strProcess]->ulRealMaxImage, strValue));
                                      ptJson->insert("resident", gpCentral->manip()->toString(ptOverall->processList[strProcess]->ulResident, strValue));
                                      ptJson->insert("min_resident", gpCentral->manip()->toString(ptOverall->processList[strProcess]->ulRealMinResident, strValue));
                                      ptJson->insert("max_resident", gpCentral->manip()->toString(ptOverall->processList[strProcess]->ulRealMaxResident, strValue));
                                      ssQuery << "select distinct c.id server_id, d.id application_contact_id, f.userid, f.email from application_server_detail a, application_server b, server c, application_contact d, contact_type e, person f where a.application_server_id=b.id and b.server_id=c.id and b.application_id=d.application_id and d.type_id=e.id and d.contact_id=f.id and a.daemon = '" << strProcess << "' and c.name = '" << (*j)->strServer << "' and (e.type = 'Primary Developer' or e.type = 'Backup Developer' or e.type = 'Primary Contact')";
                                      list<map<string, string> > *getApplicationContact = gpCentral->query("central", ssQuery.str(), strError);
                                      if (getApplicationContact != NULL)
                                      {
                                        for (list<map<string, string> >::iterator getApplicationContactIter = getApplicationContact->begin(); getApplicationContactIter != getApplicationContact->end(); getApplicationContactIter++)
                                        {
                                          map<string, string> getApplicationContactRow = *getApplicationContactIter;
                                          ssQuery.str("");
                                          ssQuery << "select count(*) num_rows from application_server_contact where application_contact_id = " << getApplicationContactRow["application_contact_id"];
                                          list<map<string, string> > *getApplicationServerContactCount = gpCentral->query("central", ssQuery.str(), strError);
                                          if (getApplicationServerContactCount != NULL && !getApplicationServerContactCount->empty())
                                          {
                                            map<string, string> getApplicationServerContactCountRow = getApplicationServerContactCount->front();
                                            if (atoi(getApplicationServerContactCountRow["num_rows"].c_str()) > 0)
                                            {
                                              ssQuery.str("");
                                              ssQuery << "select b.* from application_server a, application_server_contact b where a.id=b.application_server_id and a.server_id = " << getApplicationContactRow["server_id"] << " and b.application_contact_id = " << getApplicationContactRow["application_contact_id"];
                                              list<map<string, string> > *getApplicationServerContact = gpCentral->query("central", ssQuery.str(), strError);
                                              if (getApplicationServerContact != NULL && !getApplicationServerContact->empty())
                                              {
                                                map<string, string> getApplicationServerContactRow = getApplicationServerContact->front();
                                                contactList.push_back(getApplicationContactRow["email"]);
                                                if (ptOverall->processList[strProcess]->bPage && ptOverall->processList[strProcess]->strScript.empty())
                                                {
                                                  contactList.push_back((string)"!" + getApplicationContactRow["userid"]);
                                                }
                                              }
                                              gpCentral->free(getApplicationServerContact);
                                            }
                                            else
                                            {
                                              contactList.push_back(getApplicationContactRow["email"]);
                                              if (ptOverall->processList[strProcess]->bPage && ptOverall->processList[strProcess]->strScript.empty())
                                              {
                                                contactList.push_back((string)"!" + getApplicationContactRow["userid"]);
                                              }
                                            }
                                          }
                                          gpCentral->free(getApplicationServerContactCount);
                                        }
                                      }
                                      gpCentral->free(getApplicationContact);
                                      contactList.push_back("#nma.system");
                                      contactList.sort();
                                      contactList.unique();
                                      ptJson->m["contacts"] = new Json;
                                      for (list<string>::iterator k = contactList.begin(); k != contactList.end(); k++)
                                      {
                                        Json *ptSubJson = new Json;
                                        ptSubJson->v= *k;
                                        ptJson->m["contacts"]->l.push_back(ptSubJson);
                                      }
                                      contactList.clear();
                                      ssMessage << "script " << ptOverall->processList[strProcess]->strScript << endl << ptJson << endl;
                                      delete ptJson;
                                      (*j)->strBuffer[1] += ssMessage.str();
                                      ssMessage.str("");
                                    }
                                  }
                                  // }}}
                                }
                              }
                            }
                            // }}}
                            // {{{ system
                            else if (strAction == "system")
                            {
                              string strItem, strPartitions, strPercent, strSubToken, strToken;
                              ptOverall->strOperatingSystem = gpCentral->manip()->getToken(strToken, strLine, 2, ";");
                              ptOverall->strSystemRelease = gpCentral->manip()->getToken(strToken, strLine, 3, ";");
                              ptOverall->nProcessors = atoi(gpCentral->manip()->getToken(strToken, strLine, 4, ";").c_str());
                              ptOverall->unCpuSpeed = atoi(gpCentral->manip()->getToken(strToken, strLine, 5, ";").c_str());
                              ptOverall->usProcesses = atoi(gpCentral->manip()->getToken(strToken, strLine, 6, ";").c_str());
                              gpCentral->manip()->getToken(strToken, strLine, 7, ";").c_str();
                              ptOverall->unCpuUsage = atoi(gpCentral->manip()->getToken(strSubToken, strToken, 1, "|").c_str());
                              ptOverall->strCpuProcessUsage = gpCentral->manip()->getToken(strSubToken, strToken, 2, "|");
                              ptOverall->lUpTime = atol(gpCentral->manip()->getToken(strToken, strLine, 8, ";").c_str());
                              ptOverall->ulMainUsed = atol(gpCentral->manip()->getToken(strToken, strLine, 9, ";").c_str());
                              ptOverall->ulMainTotal = atol(gpCentral->manip()->getToken(strToken, strLine, 10, ";").c_str());
                              ptOverall->ulSwapUsed = atol(gpCentral->manip()->getToken(strToken, strLine, 11, ";").c_str());
                              ptOverall->ulSwapTotal = atol(gpCentral->manip()->getToken(strToken, strLine, 12, ";").c_str());
                              ptOverall->partition.clear();
                              gpCentral->manip()->getToken(ptOverall->strPartitions, strLine, 13, ";");
                              for (int k = 1; !gpCentral->manip()->getToken(strItem, ptOverall->strPartitions, k, ",", true).empty(); k++)
                              {
                                if (!gpCentral->manip()->getToken(strToken, strItem, 1, "=").empty())
                                {
                                  ptOverall->partition[strToken] = (unsigned int)atoi(gpCentral->manip()->getToken(strPercent, strItem, 2, "=").c_str());
                                }
                              }
                              ptOverall->bHaveValues = true;
                              // {{{ write out system alarm information
                              if (ptOverall->bHaveThresholds)
                              {
                                ptOverall->ssAlarms.str("");
                                ptOverall->bPage = false;
                                if (ptOverall->usMaxProcesses > 0 && ptOverall->usProcesses > ptOverall->usMaxProcesses)
                                {
                                  if (!ptOverall->ssAlarms.str().empty())
                                  {
                                    ptOverall->ssAlarms << ",";
                                  }
                                  ptOverall->ssAlarms << ptOverall->usProcesses << " processes are running which is more than the maximum " << ptOverall->usMaxProcesses << " processes";
                                }
                                if (ptOverall->unMaxCpuUsage > 0 && ptOverall->unCpuUsage > ptOverall->unMaxCpuUsage)
                                {
                                  if (!ptOverall->ssAlarms.str().empty())
                                  {
                                    ptOverall->ssAlarms << ",";
                                  }
                                  ptOverall->ssAlarms << "using " << ptOverall->unCpuUsage << "% CPU which is more than the maximum " << ptOverall->unMaxCpuUsage << "%";
                                  if (!ptOverall->strCpuProcessUsage.empty())
                                  {
                                    ptOverall->ssAlarms << " --- (" << ptOverall->strCpuProcessUsage << ")";
                                  }
                                }
                                if (ptOverall->unMaxMainUsage > 0 && ptOverall->ulMainTotal > 0 && (unsigned int)(ptOverall->ulMainUsed * 100 / ptOverall->ulMainTotal) >= ptOverall->unMaxMainUsage)
                                {
                                  if (!ptOverall->ssAlarms.str().empty())
                                  {
                                    ptOverall->ssAlarms << ",";
                                  }
                                  ptOverall->ssAlarms << "using " << (ptOverall->ulMainUsed * 100 / ptOverall->ulMainTotal) << "% main memory which is more than the maximum " << ptOverall->unMaxMainUsage << "%";
                                }
                                if (ptOverall->unMaxSwapUsage > 0 && ptOverall->ulSwapTotal > 0 && (unsigned int)(ptOverall->ulSwapUsed * 100 / ptOverall->ulSwapTotal) >= ptOverall->unMaxSwapUsage)
                                {
                                  ptOverall->bPage = true;
                                  if (!ptOverall->ssAlarms.str().empty())
                                  {
                                    ptOverall->ssAlarms << ",";
                                  }
                                  ptOverall->ssAlarms << "using " << (ptOverall->ulSwapUsed * 100 / ptOverall->ulSwapTotal) << "% swap memory which is more than the maximum " << ptOverall->unMaxSwapUsage << "%";
                                }
                                for (map<string, unsigned int>::iterator k = ptOverall->partition.begin(); k != ptOverall->partition.end(); k++)
                                {
                                  if (ptOverall->unMaxDiskUsage > 0 && k->second >= ptOverall->unMaxDiskUsage && k->first.find("cdrom", 0) == string::npos)
                                  {
                                    if (!ptOverall->ssAlarms.str().empty())
                                    {
                                      ptOverall->ssAlarms << ",";
                                    }
                                    ptOverall->ssAlarms << k->first << " partition is " << k->second << "% filled which is more than the maximum " << ptOverall->unMaxDiskUsage << "%";
                                  }
                                }
                                if (!ptOverall->ssAlarms.str().empty() && (ptOverall->ssPrevAlarms.str().empty() || (ptOverall->bPage && !ptOverall->bPrevPage)))
                                {
                                  ptOverall->bPrevPage = ptOverall->bPage;
                                  ptOverall->ssPrevAlarms << ptOverall->ssAlarms.str();
                                  notifyServerContact((*j)->strServer);
                                }
                              }
                              // }}}
                            }
                            // }}}
                          }
                          else
                          {
                            stringstream ssLine;
                            ssLine.str(strLine);
                            ssLine >> strAction;
                            // {{{ message
                            if (strAction == "message")
                            {
                              string strSubLine, strToken;
                              time_t CTime;
                              message *ptMessage = new message;
                              (*j)->strBuffer[1] += "okay\n";
                              gpCentral->manip()->trim(strSubLine, ssLine.str());
                              gpCentral->manip()->getToken(ptMessage->strType, strSubLine, 1, ";");
                              if (ptMessage->strType.size() >= 8 && ptMessage->strType.substr(0, 8) == "message ")
                              {
                                ptMessage->strType.erase(0, 8);
                              }
                              gpCentral->manip()->getToken(ptMessage->strApplication, strSubLine, 2, ";");
                              ptMessage->CStartTime = atoi(gpCentral->manip()->getToken(strToken, strSubLine, 3, ";").c_str());
                              ptMessage->CEndTime = atoi(gpCentral->manip()->getToken(strToken, strSubLine, 4, ";").c_str());
                              gpCentral->manip()->getToken(ptMessage->strMessage, strSubLine, 5, ";");
                              time(&CTime);
                              if (ptMessage->CEndTime > CTime)
                              {
                                gMessageList.push_back(ptMessage);
                              }
                              else
                              {
                                delete ptMessage;
                              }
                            }
                            // }}}
                            // {{{ messages
                            else if (strAction == "messages")
                            {
                              bool bFound = false;
                              time_t CTime;
                              list<list<message *>::iterator> removeSubList;
                              time(&CTime);
                              for (list<message *>::iterator k = gMessageList.begin(); k != gMessageList.end(); k++)
                              {
                                if ((*k)->CStartTime <= CTime)
                                {
                                  if ((*k)->CEndTime > CTime)
                                  {
                                    stringstream ssMessage;
                                    bFound = true;
                                    ssMessage << (*k)->strType << ";" << (*k)->strApplication << ";" << (*k)->strMessage;
                                    (*j)->strBuffer[1].append(ssMessage.str() + "\n");
                                  }
                                  else
                                  {
                                    delete *k;
                                    removeSubList.push_back(k);
                                  }
                                }
                              }
                              for (list<list<message *>::iterator>::iterator k = removeSubList.begin(); k != removeSubList.end(); k++)
                              {
                                gMessageList.erase(*k);
                              }
                              removeSubList.clear();
                              if (!bFound)
                              {
                                (*j)->bClose = true;
                              }
                            }
                            // }}}
                            // {{{ process
                            else if (strAction == "process")
                            {
                              string strServer, strProcess;
                              ssLine >> strServer >> strProcess;
                              if (!strServer.empty() && gOverallList.find(strServer) != gOverallList.end() && !strProcess.empty() && gOverallList[strServer]->processList.find(strProcess) != gOverallList[strServer]->processList.end() && gOverallList[strServer]->processList[strProcess]->bHaveValues)
                              {
                                stringstream ssDetails;
                                ssDetails << gOverallList[strServer]->processList[strProcess]->strStartTime << ';';
                                for (map<string, unsigned int>::iterator k = gOverallList[strServer]->processList[strProcess]->owner.begin(); k != gOverallList[strServer]->processList[strProcess]->owner.end(); k++)
                                {
                                  if (k != gOverallList[strServer]->processList[strProcess]->owner.begin())
                                  {
                                    ssDetails << ", ";
                                  }
                                  ssDetails << k->first << '(' << k->second << ')';
                                }
                                ssDetails << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->nProcesses << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ulImage << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ulRealMinImage << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ulRealMaxImage << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ulResident << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ulRealMinResident << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ulRealMaxResident << ';';
                                ssDetails << gOverallList[strServer]->processList[strProcess]->ssAlarms.str();
                                (*j)->strBuffer[1] += ssDetails.str() + "\n";
                              }
                              else
                              {
                                strError.clear();
                                if (strServer.empty())
                                {
                                  strError = "Please provide the server.";
                                }
                                else if (gOverallList.find(strServer) == gOverallList.end())
                                {
                                  strError = "Please provide a valid server.";
                                }
                                else if (strProcess.empty())
                                {
                                  strError = "Please provide the process.";
                                }
                                else if (gOverallList[strServer]->processList.find(strProcess) == gOverallList[strServer]->processList.end())
                                {
                                  strError = "Please provide a valid process.";
                                }
                                else if (!gOverallList[strServer]->processList[strProcess]->bHaveValues)
                                {
                                  strError = "Process has no values.";
                                }
                                (*j)->strBuffer[1] += (string)";;;;;;;;;" + strError + (string)"\n";
                              }
                            }
                            // }}}
                            // {{{ server
                            else if (strAction == "server")
                            {
                              string strServer;
                              ssLine >> strServer;
                              if (!strServer.empty())
                              {
                                bool bIPv6 = false;
                                char szIP[INET6_ADDRSTRLEN];
                                sockaddr_storage addr;
                                socklen_t len = sizeof(addr);
                                string strClient;
                                getpeername((*j)->fdData, (sockaddr*)&addr, &len);
                                if (addr.ss_family == AF_INET)
                                {
                                  sockaddr_in *s = (sockaddr_in *)&addr;
                                  inet_ntop(AF_INET, &s->sin_addr, szIP, sizeof(szIP));
                                }
                                else if (addr.ss_family == AF_INET6)
                                {
                                  sockaddr_in6 *s = (sockaddr_in6 *)&addr;
                                  bIPv6 = true;
                                  inet_ntop(AF_INET6, &s->sin6_addr, szIP, sizeof(szIP));
                                }
                                strClient = szIP;
                                // 20120824 - Ben Kietzman:  Authorization does not work right with IPv6 due to the client outgoing IP being different from the incoming IP.
                                if (bIPv6 || authorizedClient(strServer, strClient))
                                {
                                  if (gOverallList.find(strServer) == gOverallList.end())
                                  {
                                    (*j)->bClient = true;
                                    (*j)->strServer = strServer;
                                    (*j)->CStartTime = 0;
                                    gOverallList[strServer] = new overall;
                                    gOverallList[strServer]->bHaveThresholds = false;
                                    gOverallList[strServer]->bHaveValues = false;
                                    gOverallList[strServer]->bPage = false;
                                    bSync = true;
                                    chat((string)"Accepted incoming server connection from " + strServer + (string)".", strError);
                                  }
                                  else
                                  {
                                    (*j)->bClose = true;
                                    chat((string)"A secondary client request arrived for " + strServer + (string)".  Request has been denied.", strError);
                                    notify((string)"A secondary client request arrived for " + strServer + (string)".  Request has been denied.", strError);
                                  }
                                }
                                else
                                {
                                  (*j)->bClose = true;
                                  chat((string)"A client request arrived for " + strServer + (string)" which does not match the " + strClient + (string)" IP address.  Request has been denied.", strError);
                                  notify((string)"A client request arrived for " + strServer + (string)" which does not match the " + strClient + (string)" IP address.  Request has been denied.", strError);
                                }
                              }
                              else
                              {
                                (*j)->bClose = true;
                              }
                            }
                            // }}}
                            // {{{ system
                            else if (strAction == "system")
                            {
                              string strServer;
                              ssLine >> strServer;
                              if (strServer.empty())
                              {
                                bool bFound = false;
                                for (map<string, overall *>::iterator k = gOverallList.begin(); k != gOverallList.end(); k++)
                                {
                                  if (k->second->bHaveValues)
                                  {
                                    stringstream ssDetails;
                                    bFound = true;
                                    ssDetails << k->first << ';';
                                    ssDetails << k->second->strOperatingSystem << ';';
                                    ssDetails << k->second->strSystemRelease << ';';
                                    ssDetails << k->second->nProcessors << ';';
                                    ssDetails << k->second->unCpuSpeed << ';';
                                    ssDetails << k->second->usProcesses << ';';
                                    ssDetails << k->second->unCpuUsage << ';';
                                    ssDetails << k->second->lUpTime << ';';
                                    ssDetails << k->second->ulMainUsed << ';';
                                    ssDetails << k->second->ulMainTotal << ';';
                                    ssDetails << k->second->ulSwapUsed << ';';
                                    ssDetails << k->second->ulSwapTotal << ';';
                                    ssDetails << k->second->strPartitions << ';';
                                    ssDetails << k->second->ssAlarms.str();
                                    (*j)->strBuffer[1] += ssDetails.str() + "\n";
                                  }
                                }
                                if (!bFound)
                                {
                                  (*j)->strBuffer[1] += ";;;;;;;;;;;;;No servers with values exist.\n";
                                }
                              }
                              else if (gOverallList.find(strServer) != gOverallList.end())
                              {
                                if (gOverallList[strServer]->bHaveValues)
                                {
                                  stringstream ssDetails;
                                  ssDetails << strServer << ';';
                                  ssDetails << gOverallList[strServer]->strOperatingSystem << ';';
                                  ssDetails << gOverallList[strServer]->strSystemRelease << ';';
                                  ssDetails << gOverallList[strServer]->nProcessors << ';';
                                  ssDetails << gOverallList[strServer]->unCpuSpeed << ';';
                                  ssDetails << gOverallList[strServer]->usProcesses << ';';
                                  ssDetails << gOverallList[strServer]->unCpuUsage << ';';
                                  ssDetails << gOverallList[strServer]->lUpTime << ';';
                                  ssDetails << gOverallList[strServer]->ulMainUsed << ';';
                                  ssDetails << gOverallList[strServer]->ulMainTotal << ';';
                                  ssDetails << gOverallList[strServer]->ulSwapUsed << ';';
                                  ssDetails << gOverallList[strServer]->ulSwapTotal << ';';
                                  ssDetails << gOverallList[strServer]->strPartitions << ';';
                                  ssDetails << gOverallList[strServer]->ssAlarms.str();
                                  (*j)->strBuffer[1] += ssDetails.str() + "\n";
                                }
                                else
                                {
                                  (*j)->strBuffer[1] += ";;;;;;;;;;;;;Server has no values.\n";
                                }
                              }
                              else
                              {
                                (*j)->strBuffer[1] += ";;;;;;;;;;;;;Please provide a valid server.\n";
                              }
                            }
                            // }}}
                            // {{{ update
                            else if (strAction == "update")
                            {
                              (*j)->strBuffer[1] += "okay\n";
                              bSync = true;
                            }
                            // }}}
                          }
                        }
                      }
                      else
                      {
                        (*j)->bClose = true;
                      }
                    }
                    if (fds[i].revents & POLLOUT)
                    {
                      if (!(*j)->bClose && (((*j)->eSocketType == COMMON_SOCKET_ENCRYPTED && gpCentral->utility()->sslWrite((*j)->ssl, (*j)->strBuffer[1], nReturn)) || ((*j)->eSocketType == COMMON_SOCKET_UNENCRYPTED && gpCentral->utility()->fdWrite((*j)->fdData, (*j)->strBuffer[1], nReturn))))
                      {
                        if (!(*j)->bClient && (*j)->strBuffer[1].empty())
                        {
                          (*j)->bClose = true;
                        }
                      }
                      else
                      {
                        (*j)->bClose = true;
                      }
                    }
                    if ((*j)->bClose)
                    {
                      removeList.push_back(j);
                    }
                    else if ((*j)->bClient && gOverallList.find((*j)->strServer) != gOverallList.end())
                    {
                      time(&((*j)->CEndTime));
                      if ((*j)->CEndTime - (*j)->CStartTime > 30)
                      {
                        (*j)->strBuffer[1] += "system\n";
                        if (ptOverall != NULL)
                        {
                          for (map<string, process *>::iterator k = ptOverall->processList.begin(); k != ptOverall->processList.end(); k++)
                          {
                            (*j)->strBuffer[1] += (string)"process " + k->first + (string)"\n";
                          }
                        }
                        time(&((*j)->CStartTime));
                      }
                    }
                  }
                }
              }
              for (list<list<connection *>::iterator>::iterator i = removeList.begin(); i != removeList.end(); i++)
              {
                if ((*(*i))->bClient)
                {
                  gOverallList[(*(*i))->strServer]->partition.clear();
                  for (map<string, process *>::iterator j = gOverallList[(*(*i))->strServer]->processList.begin(); j != gOverallList[(*(*i))->strServer]->processList.end(); j++)
                  {
                    j->second->owner.clear();
                    delete j->second;
                  }
                  gOverallList[(*(*i))->strServer]->processList.clear();
                  delete gOverallList[(*(*i))->strServer];
                  gOverallList.erase((*(*i))->strServer);
                  //notify((string)"Lost client connection to " + (*(*i))->strServer, strError);
                }
                if ((*(*i))->eSocketType == COMMON_SOCKET_ENCRYPTED)
                {
                  SSL_shutdown((*(*i))->ssl);
                  SSL_free((*(*i))->ssl);
                }
                close((*(*i))->fdData);
                delete *(*i);
                bridge.erase(*i);
              }
              removeList.clear();
              if (bSync)
              {
                stringstream ssQuery;
                for (map<string, overall *>::iterator i = gOverallList.begin(); i != gOverallList.end(); i++)
                {
                  vector<string> remove;
                  // {{{ system
                  ssQuery.str("");
                  ssQuery << "select distinct * from server where name = \'" << i->first << "\'";
                  list<map<string, string> > *getServer = gpCentral->query("central", ssQuery.str(), strError);
                  if (getServer != NULL && !getServer->empty())
                  {
                    map<string, string> getServerRow = getServer->front();
                    i->second->unMaxCpuUsage = atoi(getServerRow["cpu_usage"].c_str());
                    i->second->unMaxDiskUsage = atoi(getServerRow["disk_size"].c_str());
                    i->second->unMaxMainUsage = atoi(getServerRow["main_memory"].c_str());
                    i->second->unMaxSwapUsage = atoi(getServerRow["swap_memory"].c_str());
                    i->second->usMaxProcesses = atoi(getServerRow["processes"].c_str());
                    i->second->bHaveThresholds = true;
                  }
                  gpCentral->free(getServer);
                  // }}}
                  // {{{ process
                  for (map<string, process *>::iterator j = i->second->processList.begin(); j != i->second->processList.end(); j++)
                  {
                    j->second->bChecking = true;
                  }
                  ssQuery.str("");
                  ssQuery << "select distinct a.* from application_server_detail a, application_server b, server c where a.application_server_id=b.id and b.server_id=c.id and a.daemon is not null and a.daemon != \'\' and c.name = \'" << i->first << "\'";
                  list<map<string, string> > *getApplicationServer = gpCentral->query("central", ssQuery.str(), strError);
                  if (getApplicationServer != NULL)
                  {
                    for (list<map<string, string> >::iterator getApplicationServerIter = getApplicationServer->begin(); getApplicationServerIter != getApplicationServer->end(); getApplicationServerIter++)
                    {
                      bool bChanged = false, bDoNothing = false;
                      map<string, string> getApplicationServerRow = *getApplicationServerIter;
                      string strProcess = getApplicationServerRow["daemon"];
                      process *ptProcess = new process;
                      ptProcess->bChecking = false;
                      ptProcess->bHaveValues = false;
                      ptProcess->bPage = false;
                      ptProcess->nDelay = atoi(getApplicationServerRow["delay"].c_str());
                      ptProcess->nProcesses = 0;
                      ptProcess->nMinProcesses = atoi(getApplicationServerRow["min_processes"].c_str());
                      ptProcess->nMaxProcesses = atoi(getApplicationServerRow["max_processes"].c_str());
                      ptProcess->ulImage = 0;
                      ptProcess->ulRealMinImage = 0;
                      ptProcess->ulRealMaxImage = 0;
                      ptProcess->ulMinImage = (unsigned long)atol(getApplicationServerRow["min_image"].c_str());
                      ptProcess->ulMaxImage = (unsigned long)atol(getApplicationServerRow["max_image"].c_str());
                      ptProcess->ulResident = 0;
                      ptProcess->ulRealMinResident = 0;
                      ptProcess->ulRealMaxResident = 0;
                      ptProcess->ulMinResident = (unsigned long)atol(getApplicationServerRow["min_resident"].c_str());
                      ptProcess->ulMaxResident = (unsigned long)atol(getApplicationServerRow["max_resident"].c_str());
                      ptProcess->CTime = 0;
                      ptProcess->strApplicationServerID = getApplicationServerRow["id"];
                      ptProcess->strOwner = getApplicationServerRow["owner"];
                      ptProcess->strScript = getApplicationServerRow["script"];
                      if (i->second->processList.find(strProcess) != i->second->processList.end())
                      {
                        i->second->processList[strProcess]->bChecking = false;
                        if (i->second->processList[strProcess]->nMinProcesses != ptProcess->nMinProcesses || i->second->processList[strProcess]->nMaxProcesses != ptProcess->nMaxProcesses || i->second->processList[strProcess]->ulMinImage != ptProcess->ulMinImage || i->second->processList[strProcess]->ulMaxImage != ptProcess->ulMaxImage || i->second->processList[strProcess]->ulMinResident != ptProcess->ulMinResident || i->second->processList[strProcess]->ulMaxResident != ptProcess->ulMaxResident || i->second->processList[strProcess]->strOwner != ptProcess->strOwner || i->second->processList[strProcess]->strScript != ptProcess->strScript)
                        {
                          bChanged = true;
                        }
                        if (bChanged)
                        {
                          i->second->processList[strProcess]->owner.clear();
                          delete i->second->processList[strProcess];
                          i->second->processList.erase(strProcess);
                        }
                        else
                        {
                          bDoNothing = true;
                        }
                      }
                      if (bDoNothing)
                      {
                        delete ptProcess;
                      }
                      else
                      {
                        i->second->processList[strProcess] = ptProcess;
                      }
                    }
                  }
                  gpCentral->free(getApplicationServer);
                  for (map<string, process *>::iterator j = i->second->processList.begin(); j != i->second->processList.end(); j++)
                  {
                    if (j->second->bChecking)
                    {
                      remove.push_back(j->first);
                      j->second->owner.clear();
                      delete j->second;
                    }
                  }
                  for (vector<string>::iterator j = remove.begin(); j != remove.end(); j++)
                  {
                    i->second->processList.erase(*j);
                  }
                  remove.clear();
                  // }}}
                }
              }
            }
            else if (nReturn < 0 && errno != EINTR)
            {
              bExit = true;
              notify((string)"Poll error: " + strerror(errno), strError);
            }
            delete[] fds;
          }
          for (list<connection *>::iterator i = bridge.begin(); i != bridge.end(); i++)
          {
            delete *i;
          }
          bridge.clear();
          ssMessage << "Lost connection to status socket!  " << strerror(errno) << "(" << errno << ").  Exiting...";
          notify(ssMessage.str(), strError);
        }
        else
        {
          notify("Could not listen to status socket!  Exiting...", strError);
        }
        close(gfdStatus);
      }
      else
      {
        gpCentral->alert("Could not bind to the socket!  Exiting...", strError);
      }
    }
    else
    {
      gpCentral->alert((string)"Could not get address information!  (" + (string)gai_strerror(nReturn) + (string)")  Exiting...", strError);
    }
  }
  // }}}
  // {{{ usage statement
  else
  {
    mUSAGE(argv[0]);
  }
  // }}}
  if (ctx != NULL)
  {
    SSL_CTX_free(ctx);
  }
  gpCentral->utility()->sslDeinit();
  gCred.clear();
  if (gpSyslog != NULL)
  {
    delete gpSyslog;
  }
  delete gpCentral;
  delete gpJunction;

  return 0;
}
// }}}
// {{{ authorizedClient()
bool authorizedClient(const string strServer, const string strClient)
{
  bool bResult = false;
  struct addrinfo hints;
  struct addrinfo *result;
  int nReturn;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;
  if ((nReturn = getaddrinfo(strServer.c_str(), NULL, &hints, &result)) == 0)
  {
    struct addrinfo *rp;
    string strIP;
    for (rp = result; !bResult && rp != NULL; rp = rp->ai_next)
    {
      char szIP[INET6_ADDRSTRLEN];
      if (rp->ai_family == AF_INET)
      {
        sockaddr_in *s = (sockaddr_in *)rp->ai_addr;
        inet_ntop(AF_INET, &s->sin_addr, szIP, sizeof(szIP));
      }
      else if (rp->ai_family == AF_INET6)
      {
        sockaddr_in6 *s = (sockaddr_in6 *)rp->ai_addr;
        inet_ntop(AF_INET6, &s->sin6_addr, szIP, sizeof(szIP));
      }
      strIP = szIP;
      if (strIP.find(".", 0) != string::npos && (strIP.size() < 7 || strIP.substr(0, 7) != "::ffff:"))
      {
        strIP = (string)"::ffff:" + strIP;
      }
      if (strClient == strIP)
      {
        bResult = true;
      }
    }
    freeaddrinfo(result);
  }

  return bResult;
}
// }}}
// {{{ chat()
bool chat(const string strMessage, string &strError)
{
  bool bResult = false;
  Json *ptRequest = new Json, *ptResponse = new Json;

  ptRequest->insert("Section", "chat");
  ptRequest->insert("Function", "application");
  ptRequest->m["Request"] = new Json;
  ptRequest->m["Request"]->insert("Message", strMessage);
  ptRequest->m["Request"]->insert("Target", gstrRoom);
  if (gpJunction->bridge(gCred["User"], gCred["Password"], ptRequest, ptResponse, strError))
  {
    bResult = true;
  }
  else
  {
    notify((string)"Failed to chat the following message:  " + strMessage + (string)" --- " + strError, strError);
  }
  delete ptRequest;
  delete ptResponse;

  return bResult;
}
// }}}
// {{{ notify()
bool notify(const string strMessage, string &strError)
{
  bool bResult = false;
  list<string> toList, ccList, bccList, fileList;
  utsname tServer;

  uname(&tServer);
  toList.push_back(gstrEmail);
  if (gpCentral->junction()->email((string)"root@"+(string)tServer.nodename, toList, ccList, bccList, gstrApplication, strMessage, "", fileList, strError))
  {
    bResult = true;
  }
  toList.clear();

  return bResult;
}
// }}}
// {{{ notifyApplicationContact()
void notifyApplicationContact(const string strServer, const string strProcess)
{
  if (gOverallList.find(strServer) != gOverallList.end() && gOverallList[strServer]->processList.find(strProcess) != gOverallList[strServer]->processList.end())
  {
    struct utsname tServer;
    list<string> toList, ccList, bccList, fileList, pageList;
    string strError, strMessage = gOverallList[strServer]->processList[strProcess]->ssAlarms.str(), strSubject;
    stringstream ssQuery;
    uname(&tServer);
    strSubject = ((!strServer.empty())?strServer:(string)tServer.nodename);
    ssQuery << "select distinct c.id server_id, d.id application_contact_id, f.userid, f.email from application_server_detail a, application_server b, server c, application_contact d, contact_type e, person f where a.application_server_id=b.id and b.server_id=c.id and b.application_id=d.application_id and d.type_id=e.id and d.contact_id=f.id and a.daemon = '" << strProcess << "' and c.name = '" << strServer << "' and (e.type = 'Primary Developer' or e.type = 'Backup Developer' or e.type = 'Primary Contact')";
    list<map<string, string> > *getApplicationContact = gpCentral->query("central", ssQuery.str(), strError);
    if (getApplicationContact != NULL)
    {
      for (list<map<string, string> >::iterator getApplicationContactIter = getApplicationContact->begin(); getApplicationContactIter != getApplicationContact->end(); getApplicationContactIter++)
      {
        map<string, string> getApplicationContactRow = *getApplicationContactIter;
        ssQuery.str("");
        ssQuery << "select count(*) num_rows from application_server_contact where application_contact_id = " << getApplicationContactRow["application_contact_id"];
        list<map<string, string> > *getApplicationServerContactCount = gpCentral->query("central", ssQuery.str(), strError);
        if (getApplicationServerContactCount != NULL && !getApplicationServerContactCount->empty())
        {
          map<string, string> getApplicationServerContactCountRow = getApplicationServerContactCount->front();
          if (atoi(getApplicationServerContactCountRow["num_rows"].c_str()) > 0)
          {
            ssQuery.str("");
            ssQuery << "select b.* from application_server a, application_server_contact b where a.id=b.application_server_id and a.server_id = " << getApplicationContactRow["server_id"] << " and b.application_contact_id = " << getApplicationContactRow["application_contact_id"];
            list<map<string, string> > *getApplicationServerContact = gpCentral->query("central", ssQuery.str(), strError);
            if (getApplicationServerContact != NULL && !getApplicationServerContact->empty())
            {
              map<string, string> getApplicationServerContactRow = getApplicationServerContact->front();
              toList.push_back(getApplicationContactRow["email"]);
              if (gOverallList[strServer]->processList[strProcess]->bPage && gOverallList[strServer]->processList[strProcess]->strScript.empty())
              {
                if (!gpCentral->junction()->page(getApplicationContactRow["userid"], gstrApplication + (string)":  " + strSubject + (string)"\n\n" + strMessage, strError))
                {
                  stringstream ssError;
                  ssError << "notifyApplicationContact()->central->junction()->page() error [" << strServer << "," << strProcess << "," << getApplicationContactRow["userid"] << "]:  " << strError;
                  notify(ssError.str(), strError);
                }
              }
            }
            gpCentral->free(getApplicationServerContact);
          }
          else
          {
            toList.push_back(getApplicationContactRow["email"]);
            if (gOverallList[strServer]->processList[strProcess]->bPage && gOverallList[strServer]->processList[strProcess]->strScript.empty())
            {
              if (!gpCentral->junction()->page(getApplicationContactRow["userid"], gstrApplication + (string)":  " + strSubject + (string)"\n\n" + strMessage, strError))
              {
                stringstream ssError;
                ssError << "notifyApplicationContact()->central->junction()->page() error [" << strServer << "," << strProcess << "," << getApplicationContactRow["userid"] << "]:  " << strError;
                notify(ssError.str(), strError);
              }
            }
          }
        }
        gpCentral->free(getApplicationServerContactCount);
      }
    }
    gpCentral->free(getApplicationContact);
    if (!chat(strSubject + (string)":  " + strMessage, strError))
    {
      stringstream ssError;
      ssError << "notifyApplicationContact()->chat() error [" << strServer << "," << strProcess << "]:  " << strError;
      notify(ssError.str(), strError);
    }
    if (!toList.empty())
    {
      if (!gpCentral->junction()->email((string)"root@" + (string)tServer.nodename, toList, ccList, bccList, gstrApplication + (string)":  " + strSubject, strMessage, "", fileList, strError))
      {
        stringstream ssError;
        ssError << "notifyApplicationContact()->central->junction()->email() error [" << strServer << "," << strProcess;
        for (list<string>::iterator i = toList.begin(); i != toList.end(); i++)
        {
          ssError << "," << (*i);
        }
        ssError << "]:  " << strError;
        notify(ssError.str(), strError);
      }
    }
  }
}
// }}}
// {{{ notifyServerContact()
void notifyServerContact(const string strServer)
{
  struct utsname tServer;
  list<string> toList, ccList, bccList, fileList;
  string strError, strMessage = gOverallList[strServer]->ssAlarms.str(), strSubject;
  stringstream ssQuery;

  uname(&tServer);
  strSubject = ((!strServer.empty())?strServer:(string)tServer.nodename);
  ssQuery << "select d.userid, d.email from server_contact a, server b, contact_type c, person d where a.server_id=b.id and a.type_id=c.id and a.contact_id=d.id and b.name = '" << strServer << "' and (c.type = 'Primary Admin' or c.type = 'Backup Admin' or c.type = 'Primary Contact') and a.notify = 1";
  list<map<string, string> > *getServerContact = gpCentral->query("central", ssQuery.str(), strError);
  if (getServerContact != NULL)
  {
    for (list<map<string, string> >::iterator getServerContactIter = getServerContact->begin(); getServerContactIter != getServerContact->end(); getServerContactIter++)
    {
      map<string, string> getServerContactRow = *getServerContactIter;
      toList.push_back(getServerContactRow["email"]);
      if (gOverallList[strServer]->bPage)
      {
        if (!gpCentral->junction()->page(getServerContactRow["userid"], gstrApplication + (string)":  " + strSubject + (string)"\n\n" + strMessage, strError))
        {
          stringstream ssError;
          ssError << "notifyServerContact()->central->junction()->page() error [" << strServer << "," << getServerContactRow["userid"] << "]:  " << strError;
          notify(ssError.str(), strError);
        }
      }
    }
  }
  gpCentral->free(getServerContact);
  if (!chat(strSubject + (string)":  " + strMessage, strError))
  {
    stringstream ssError;
    ssError << "notifyServerContact()->chat() error [" << strServer << "]:  " << strError;
    notify(ssError.str(), strError);
  }
  if (!toList.empty())
  {
    if (!gpCentral->junction()->email((string)"root@" + (string)tServer.nodename, toList, ccList, bccList, gstrApplication + (string)":  " + strSubject, strMessage, "", fileList, strError))
    {
      stringstream ssError;
      ssError << "notifyServerContact()->central->junction()->email() error [" << strServer;
      for (list<string>::iterator i = toList.begin(); i != toList.end(); i++)
      {
        ssError << "," << (*i);
      }
      ssError << "]:  " << strError;
      notify(ssError.str(), strError);
    }
  }
}
// }}}
// {{{ sighandle()
void sighandle(const int nSignal)
{
  list<string> dir;
  string strError, strSignal;
  stringstream ssSignal, ssCore;

  sethandles(sigdummy);
  gbShutdown = true;
  if (nSignal != SIGINT && nSignal != SIGTERM)
  {
    ssSignal << nSignal;
    notify((string)"The program's signal handling caught a " + (string)sigstring(strSignal, nSignal) + (string)"(" + ssSignal.str() + (string)")!  Exiting...", strError);
  }
  close(gfdStatus);
  exit(1);
}
// }}}
