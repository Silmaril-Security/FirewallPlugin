export type TelegramUpdate = {
  update_id: number;
  message?: {
    message_id: number;
    date: number;
    text?: string;
    chat: {
      id: number;
      type: "private" | "group" | "supergroup" | "channel";
      first_name?: string;
      username?: string;
    };
    from?: {
      id: number;
      is_bot: boolean;
      first_name?: string;
      username?: string;
    };
  };
};

export type TelegramOkResponse<T> = {
  ok: true;
  result: T;
};
