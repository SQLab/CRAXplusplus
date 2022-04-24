void putsStreets(void) {
    puts("We meet again on these pwning streets.");
}

ssize_t __fastcall vuln(void *a1) {
  puts("What an interesting thing to say.\nTell me more.");
  read(0, a1, 0x7DAuLL);  // 2010
  return write(1, "Fascinating.\n", 0xDuLL);  // 13
}

int callsVuln() {
  int result; // eax@2
  char buf; // [sp+0h] [bp-590h]@1
  char v2; // [sp+190h] [bp-400h]@2

  puts("What say you now?");
  read(0, &buf, 0x12CuLL);  // 300

  if (!strncmp(&buf, "Everything intelligent is so boring.", 0x24uLL))  // 36
    result = vuln(&v2);
  else
    result = puts("What a ho-hum thing to say.");

  return result;
}

void putsFare(void) {
    puts("Fare thee well.");
}


__int64 __fastcall main(__int64 a1, char **a2, char **a3) {
  setvbuf(stdout, 0LL, 2, 0LL);

  if (!getenv("DEBUG"))
    alarm(5u);

  putsStreets();
  callsVuln();
  putsFare();
  return 0LL;
}
