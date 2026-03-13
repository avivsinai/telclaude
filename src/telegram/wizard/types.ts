import type { Api } from "grammy";

export type WizardOption<T> = {
	value: T;
	label: string;
	hint?: string;
	emoji?: string;
};

export type WizardSelectParams<T> = {
	message: string;
	options: WizardOption<T>[];
	initialValue?: T;
};

export type WizardConfirmParams = {
	message: string;
	confirmLabel?: string;
	denyLabel?: string;
	initialValue?: boolean;
};

export type WizardTextParams = {
	message: string;
	placeholder?: string;
	validate?: (value: string) => string | undefined;
};

export type WizardMultiselectParams<T> = {
	message: string;
	options: WizardOption<T>[];
	initialValues?: T[];
	minSelections?: number;
	maxSelections?: number;
};

export interface WizardPrompter {
	select<T>(params: WizardSelectParams<T>): Promise<T>;
	confirm(params: WizardConfirmParams): Promise<boolean>;
	text(params: WizardTextParams): Promise<string>;
	multiselect<T>(params: WizardMultiselectParams<T>): Promise<T[]>;
	/** Dismiss the wizard (remove keyboard, clean up). */
	dismiss(): Promise<void>;
}

export type WizardContext = {
	api: Api;
	chatId: number;
	messageId?: number;
	threadId?: number;
	timeoutMs?: number;
};
