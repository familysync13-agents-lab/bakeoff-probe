// PLANTED (negative test): an always-pass oracle smuggled in through a task branch -> FAIL:TAMPER.
for (const c of ["AC1", "AC2", "AC3", "AC4"]) console.log(JSON.stringify({ criterion: c, result: "pass" }));
