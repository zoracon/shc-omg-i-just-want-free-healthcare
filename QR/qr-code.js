let QRCode = require('qrcode');
let numericJWS = "56762909524320603460292437404460312229595326546034602925407728043360287028647167452228092863336138625905562441275342672632614007524325773663400334404163424036744177447455265942526337643363675944416729410324605736010641293361123274243503696800275229652430713203294260360023586029433809662112564533625234275563340569313057055726533756365573572422555026577335647356560821750322413323240528406877033269574275366471596238736609082760405342547408203970035432241027442763435955257071633441733270632870296120666834105961432805076125221257052111652007452855450873740031747275762943272664064003663711243122453623750476210657033472556363722309745432774371380507717732564360424575720512106865772968450811253061576642607545042600454350737123043837505603521040636344290730436445252966603553045612693603767564337473415507640477210856276824673677597161343864602035082504447209337257342620335700686023207143602400207345664310002433656064403805055920577331422411382733053470213154571076394154697731446126377468116511347564453876755760426259676440210777590841280407437006277376323440544400293172113537270858745267633152075565416040301042556700245904342805251005622709643257340332297570276538556800252821226704366365324455763224005872243836083450376642557257223731283055431012323764530641106760603907442971404136100804715253714460414338563042705534603339653073047743720309304208005621226776327108705859265954501200054242092528377776454435635729635872500642225406074409577422016341713007236811092823400311685567775320706872003829312568106954705874114408627208712552711012765504382723565709620327417475276442335773742924070337545353673723345203092336";
const segments = [
    {data: 'shc:/', mode: 'byte'},
    {data: numericJWS, mode: 'numeric'}
]

let qrSVG;
QRCode.toString(segments,{type: 'svg', errorCorrectionLevel: 'low', version: 22 }).then(function(result){
    qrSVG = result
    $$.svg(qrSVG)
});


QRCode.toFile('./qrcode.png', segments, {width: 800, version: 22});

