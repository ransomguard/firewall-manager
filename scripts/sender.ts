import net from "node:net";
import path from "node:path";



const PIPE_NAME = "\\\\.\\pipe\\Ransom0_Firewall";



export async function main(
    pipeName: string,
    action: string,
    {
        args = [],
    }: {
        args?: string[];
    } = {},
) {
    return new Promise<string>((resolve, reject) => {
        if (!action) {
            reject(new Error("No action specified. Usage: sender.ts <action> [args]"));
        }

        const client = net.createConnection(pipeName, () => {
            // 1. 전송할 JSON 페이로드 (끝에 \n 필수)
            const whitelist = action !== "set" && !args.length ? undefined : args;
            const payload = JSON.stringify({
                action,
                whitelist,
            }) + "\n";
            client.write(payload);
        });

        // 2. 엔진 응답 수신
        client.on("data", (data) => {
            resolve(data);
            client.end(); // 확인 후 연결 종료
        });

        // 3. 에러 처리 (엔진이 켜져 있지 않을 때 등)
        client.on("error", (err) => {
            reject(err);
        });
    });
}



if (import.meta.main) {
    // bun sender.ts on 1.2.3.4 4.3.2.0/24

    process.argv.shift();
    const fileName = path.basename(process.argv.shift() || "");
    const action = process.argv.shift();
    const args = [...process.argv];

    const logger = (
        level: "debug" | "info" | "warn" | "error",
        ...messages: string[]
    ) => console[level](`[${fileName}] ${messages.join(" ")}`);

    logger("info", "Request:", action, args.join(" "));
    const response = await main(PIPE_NAME, action, { args });
    logger("info", "Response:", response.toString());
}
