// vim600: fdm=marker
/* -*- c++ -*- */
///////////////////////////////////////////
// Central Monitor
// -------------------------------------
// file       : centralmon_trigger.cpp
// author     : Ben Kietzman
// begin      : 2013-11-18
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

/*! \file centralmon_trigger.cpp
* \brief Central Monitor
*
* Processes Central Monitor alarms the specified daemon.
*/
// {{{ includes
#include <cstdlib>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <sys/utsname.h>
using namespace std;
#include <Central>
#include <Json>
using namespace common;
// }}}
// {{{ main()
/*! \fn int main(int argc, char *argv[])
* \brief This is the main function.
* \return Exits with a return code for the operating system.
*/
int main(int argc, char *argv[])
{
  string strError, strJson;
  Central *pCentral = new Central(strError);

  pCentral->setApplication("Central Monitor");
  if (getline(cin, strJson))
  {
    Json *ptJson = new Json(strJson);
    if (ptJson->m.find("daemon") != ptJson->m.end() && !pCentral->utility()->isProcessAlreadyRunning(ptJson->m["daemon"]->v))
    {
      stringstream ssCommand[2];
      #ifdef LINUX
      if (pCentral->file()->directoryExist("/etc/init"))
      {
        ssCommand[0] << "service " << ptJson->m["daemon"]->v << " stop";
        ssCommand[1] << "service " << ptJson->m["daemon"]->v << " start";
      }
      else
      {
        ssCommand[0] << "/etc/init.d/" << ptJson->m["daemon"]->v << " stop";
        ssCommand[1] << "/etc/init.d/" << ptJson->m["daemon"]->v << " start";
      }
      #else
      ssCommand[0] << "svcadm disable " << ptJson->m["daemon"]->v;
      ssCommand[1] << "svcadm enable " << ptJson->m["daemon"]->v;
      #endif
      system(ssCommand[0].str().c_str());
      system(ssCommand[1].str().c_str());
      if (!pCentral->utility()->isProcessAlreadyRunning(ptJson->m["daemon"]->v))
      {
        struct utsname tServer;
        if (uname(&tServer) == 0)
        {
          list<string> contact;
          stringstream ssMessage;
          ssMessage << "Failed to restart the " << ptJson->m["daemon"]->v << " daemon after it stopped.  Attempted starting the daemon with the following command:  " << ssCommand[1].str();
          for (int i = 1; i < argc; i++)
          {
            contact.push_back(argv[i]);
          }
          if (ptJson->m.find("contacts") != ptJson->m.end())
          {
            for (list<Json *>::iterator i = ptJson->m["contacts"]->l.begin(); i != ptJson->m["contacts"]->l.end(); i++)
            {
              if (!(*i)->v.empty())
              {
                contact.push_back((*i)->v);
              }
            }
          }
          contact.sort();
          contact.unique();
          for (list<string>::iterator i = contact.begin(); i != contact.end(); i++)
          {
            string strContact = *i;
            if (strContact[0] == '!')
            {
              strContact.erase(0, 1);
              if (!pCentral->junction()->page(strContact, (string)"Central Monitor: " + ssMessage.str(), strError))
              {
                cerr << "Failed to page message to " << strContact << "." << endl;
              }
            }
            else
            {
              list<string> toList, ccList, bccList, fileList;
              stringstream ssHtml, ssText;
              toList.push_back(strContact);
              ssText << "--- Central Monitor ---" << endl << endl << ssMessage.str() << endl;
              ssHtml << "<html><body><b>--- Central Monitor ---</b><br><br>" << ssMessage.str() << endl;
              if (!pCentral->junction()->email((string)"root@" + (string)tServer.nodename, toList, ccList, bccList, (string)"Central Monitor:  " + ptJson->m["daemon"]->v + " daemon", ssText.str(), ssHtml.str(), fileList, strError))
              {
                cerr << "Failed to send email to " << strContact << "." << endl;
              }
              toList.clear();
            }
          }
          contact.clear();
        }
        else
        {
          cerr << "Failed to retrieve the local server." << endl;
        }
      }
    }
    else
    {
      cerr << "Please provide the daemon field in the JSON data on standard input." << endl;
    }
  }
  else
  {
    cerr << "Please provide the JSON data on standard input." << endl;
  }
  delete pCentral;

  return 0;
}
// }}}
