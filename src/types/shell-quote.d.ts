declare module "shell-quote" {
	export function parse(input: string): Array<string | { op: string }>;
}
