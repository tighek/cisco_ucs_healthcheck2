#!/usr/bin/python

#
# UCS Health Check  -  Appliance Login Menu
#
# Copyright 2015 Rusty Buzhardt and Tighe Kuykendall
#
# Licensed under the Apache License, Version 2.0 (the "License") available
# at  http://www.apache.org/licenses/LICENSE-2.0.  You may not use this
# script except in compliance with the License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from os import system
import curses

def get_param(prompt_string):
     screen.clear()
     screen.border(0)
     screen.addstr(2, 2, prompt_string)
     screen.refresh()
     input = screen.getstr(10, 10, 60)
     return input

def execute_cmd(cmd_string):
     system("clear")
     a = system(cmd_string)
     print ""
     if a == 0:
          print "Command executed correctly"
     else:
          print "Command terminated with error"
     raw_input("Press enter")
     print ""

x = 0

while x != ord('4'):
     screen = curses.initscr()

     screen.clear()
     screen.border(0)
     screen.addstr(2, 2, "Please enter a number...")
     screen.addstr(4, 4, "1 - Start UCS Health Check")
#     screen.addstr(5, 4, "2 - Restart Apache")
#     screen.addstr(6, 4, "3 - Show disk space")
     screen.addstr(7, 4, "4 - Exit")
     screen.refresh()

     x = screen.getch()

     if x == ord('1'):
          curses.endwin()
          execute_cmd("python UCS_HealthCheck.py")
     if x == ord('2'):
          curses.endwin()
          execute_cmd("apachectl restart")
     if x == ord('3'):
          curses.endwin()
          execute_cmd("df -h")

curses.endwin()



